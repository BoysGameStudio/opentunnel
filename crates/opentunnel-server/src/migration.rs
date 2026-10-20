//! Exports and imports of every tunnel record, in the format the Cloudflare Worker's export introduced, for
//! backups and restores. Imported records are checked as
//! strictly as the API checks its own writes: a record could otherwise make the server order a certificate for
//! any name in the zone (`csr::check_tunnel_request`).

use anyhow::Result;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::warn;

use crate::clock::Clock;
use crate::record::StoredTunnel;
use crate::store::{ImportOutcome, Store};

/// The export file, as `opentunnel-server export` and `POST /api/admin/export` write it (and the Worker's export did).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFile {
    pub version: u32,
    #[serde(default)]
    pub exported_at: Option<String>,
    pub records: Vec<ExportedRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedRecord {
    /// The Durable Object ID, when exported from the Worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub record: Option<StoredTunnel>,
    /// The renewal alarm, Unix milliseconds.
    #[serde(default)]
    pub alarm: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
pub struct ImportSummary {
    pub inserted: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub kept_local: usize,
    pub skipped: usize,
    /// Records refused by [`check`], with why.
    pub rejected: Vec<String>,
    pub ids: Vec<String>,
}

/// Whether an imported record is one this server could have written for `domain`: a tunnel ID as a DNS label,
/// its hostname, a token hash, and a certificate request only for the tunnel's own names.
pub fn check(record: &StoredTunnel, domain: &str) -> Result<(), String> {
    if !crate::csr::valid_tunnel_id(&record.id) {
        return Err(format!("{:?} is not a tunnel ID", record.id));
    }
    let hostname = format!("{}.{domain}", record.id);
    if record.hostname != hostname {
        return Err(format!("hostname {:?} is not {hostname}", record.hostname));
    }
    let hex = |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !hex(&record.token_hash) {
        return Err("the token hash is not SHA-256 hex".into());
    }
    match (&record.certificate_csr, &record.certificate_identifiers) {
        (Some(csr), _) => {
            crate::csr::check_tunnel_request(&record.id, domain, &record.identifiers(), csr)
        }
        (None, Some(identifiers)) => {
            crate::csr::check_tunnel_names(&record.id, domain, identifiers)
        }
        (None, None) => Ok(()),
    }
}

/// Imports records. Rows this server changed since they were imported are kept unless `force`.
pub async fn import(
    store: &Store,
    clock: &Clock,
    domain: &str,
    file: ExportFile,
    force: bool,
) -> Result<ImportSummary> {
    anyhow::ensure!(
        file.version == 1,
        "unsupported export version {}",
        file.version
    );
    let mut summary = ImportSummary::default();
    for entry in file.records {
        let Some(record) = entry.record else {
            summary.skipped += 1;
            continue;
        };
        if let Err(reason) = check(&record, domain) {
            warn!(tunnel = %record.id, reason, "refused an imported record");
            summary.rejected.push(format!("{}: {reason}", record.id));
            continue;
        }
        let alarm = entry
            .alarm
            .filter(|alarm| *alarm > 0.0)
            .map(|alarm| alarm as u64);
        let id = record.id.clone();
        match store
            .import_tunnel(record, alarm, force, clock.now_ms())
            .await?
        {
            ImportOutcome::Inserted => summary.inserted += 1,
            ImportOutcome::Updated => summary.updated += 1,
            ImportOutcome::Unchanged => summary.unchanged += 1,
            ImportOutcome::KeptLocal => summary.kept_local += 1,
        }
        summary.ids.push(id);
    }
    Ok(summary)
}

/// Tunnels read per query of an export. Records are a few KB each (certificate chains and CSRs), so a page stays
/// far below PlanetScale's 64 MiB result limit, which the whole table passed at ~17,000 tunnels.
pub const EXPORT_PAGE: usize = 500;

/// An export file, read a page at a time (keyset by ID) and sent as it is read: the opening with `records: [`,
/// one record per line, then the closing. Readers of the whole file see the same [`ExportFile`] as ever. Pages are
/// read one after another, not in one transaction, so a record changed meanwhile is exported as it was when its
/// page was read. A failure is sent last; whatever was sent before it is not a complete file.
pub fn export(store: Store, clock: Clock, page: usize) -> mpsc::Receiver<Result<Bytes>> {
    let (tx, rx) = mpsc::channel(4);
    tokio::spawn(async move {
        let result = export_pages(&store, &clock, page.max(1), &tx).await;
        if let Err(error) = result {
            warn!(error = %format!("{error:#}"), "export failed");
            let _ = tx.send(Err(error)).await;
        }
    });
    rx
}

async fn export_pages(
    store: &Store,
    clock: &Clock,
    page: usize,
    tx: &mpsc::Sender<Result<Bytes>>,
) -> Result<()> {
    let send = |chunk: Vec<u8>| async {
        tx.send(Ok(Bytes::from(chunk)))
            .await
            .map_err(|_| anyhow::anyhow!("the export's reader went away"))
    };
    let opening = format!(
        "{{\"version\":1,\"exportedAt\":{},\"records\":[",
        serde_json::to_string(&clock.iso())?
    );
    send(opening.into_bytes()).await?;
    let mut after: Option<String> = None;
    let mut first = true;
    loop {
        let rows = store.export_page(after.as_deref(), page).await?;
        let Some((last, _, _)) = rows.last() else {
            break;
        };
        after = Some(last.clone());
        let full = rows.len() == page;
        let mut chunk = Vec::new();
        for (_, record, alarm) in rows {
            chunk.extend_from_slice(if first { b"\n" } else { b",\n" });
            first = false;
            serde_json::to_writer(
                &mut chunk,
                &ExportedRecord {
                    object_id: None,
                    record: Some(record),
                    alarm: alarm.map(|alarm| alarm as f64),
                },
            )?;
        }
        send(chunk).await?;
        if !full {
            break;
        }
    }
    send(b"\n]}\n".to_vec()).await
}
