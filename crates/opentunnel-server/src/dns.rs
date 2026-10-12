//! DNS-01 challenge records. DNS for the domain stays on Cloudflare; the provider is an enum so another can be
//! added without touching issuance.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

#[derive(Clone)]
pub enum DnsProvider {
    /// The Cloudflare DNS API, with a token that can edit the zone.
    Cloudflare {
        http: reqwest::Client,
        api: String,
        zone_id: String,
        token: String,
    },
    /// pebble-challtestsrv's management API, for testing against Pebble.
    ChallTestSrv { http: reqwest::Client, url: String },
}

/// A created TXT record, to delete afterwards.
#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub name: String,
    pub value: String,
    pub id: Option<String>,
}

#[derive(Deserialize)]
struct CloudflareResponse<A> {
    success: bool,
    result: Option<A>,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

#[derive(Deserialize)]
struct CloudflareError {
    #[serde(default)]
    code: u64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Listed {
    id: String,
    #[serde(default)]
    content: String,
}

/// Cloudflare's error for a record that exists with the same name and content.
const CLOUDFLARE_IDENTICAL_RECORD: u64 = 81058;

#[derive(Deserialize)]
struct Created {
    id: String,
}

impl DnsProvider {
    /// Creates a TXT record `name` (a full name, `_acme-challenge.<host>`) with `value`, TTL 60. A record that
    /// already exists with that value (left by an interrupted attempt) is used as is, and deleted afterwards
    /// like a created one.
    pub async fn create_txt(&self, name: &str, value: &str) -> Result<TxtRecord> {
        match self {
            Self::Cloudflare {
                http,
                api,
                zone_id,
                token,
            } => {
                let response = http
                    .post(format!("{api}/zones/{zone_id}/dns_records"))
                    .bearer_auth(token)
                    .timeout(Duration::from_secs(30))
                    .json(&json!({ "type": "TXT", "name": name, "content": value, "ttl": 60 }))
                    .send()
                    .await?;
                let status = response.status();
                let body: CloudflareResponse<Created> = response
                    .json()
                    .await
                    .map_err(|_| anyhow!("DNS record creation failed"))?;
                match body.result {
                    Some(created) if status.is_success() && body.success => Ok(TxtRecord {
                        name: name.into(),
                        value: value.into(),
                        id: Some(created.id),
                    }),
                    _ if body.errors.iter().any(|error| {
                        error.code == CLOUDFLARE_IDENTICAL_RECORD
                            || error.message.contains("identical record already exists")
                    }) =>
                    {
                        let id = self.find_txt(name, value).await.unwrap_or_else(|error| {
                            warn!(%error, name, "failed to look up an existing challenge record");
                            None
                        });
                        Ok(TxtRecord {
                            name: name.into(),
                            value: value.into(),
                            id,
                        })
                    }
                    _ => {
                        let messages: Vec<String> = body
                            .errors
                            .into_iter()
                            .map(|error| error.message)
                            .filter(|message| !message.is_empty())
                            .collect();
                        if messages.is_empty() {
                            bail!("DNS record creation failed")
                        }
                        bail!("{}", messages.join(", "))
                    }
                }
            }
            Self::ChallTestSrv { http, url } => {
                let response = http
                    .post(format!("{url}/set-txt"))
                    .json(&json!({ "host": format!("{name}."), "value": value }))
                    .send()
                    .await?;
                if !response.status().is_success() {
                    bail!(
                        "DNS record creation failed: HTTP {}",
                        response.status().as_u16()
                    );
                }
                Ok(TxtRecord {
                    name: name.into(),
                    value: value.into(),
                    id: None,
                })
            }
        }
    }

    /// The ID of the Cloudflare TXT record `name` with `value`, if there is one.
    async fn find_txt(&self, name: &str, value: &str) -> Result<Option<String>> {
        let Self::Cloudflare {
            http,
            api,
            zone_id,
            token,
        } = self
        else {
            return Ok(None);
        };
        let mut url = url::Url::parse(&format!("{api}/zones/{zone_id}/dns_records"))?;
        url.query_pairs_mut()
            .append_pair("type", "TXT")
            .append_pair("name", name);
        let body: CloudflareResponse<Vec<Listed>> = http
            .get(url)
            .bearer_auth(token)
            .timeout(Duration::from_secs(30))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // Cloudflare may show TXT content quoted.
        Ok(body
            .result
            .unwrap_or_default()
            .into_iter()
            .find(|record| record.content.trim_matches('"') == value)
            .map(|record| record.id))
    }

    /// Deletes a record, logging rather than failing: a leftover TXT record is harmless.
    pub async fn delete_txt(&self, record: &TxtRecord) {
        let result = match self {
            Self::Cloudflare {
                http,
                api,
                zone_id,
                token,
            } => match &record.id {
                Some(id) => http
                    .delete(format!("{api}/zones/{zone_id}/dns_records/{id}"))
                    .bearer_auth(token)
                    .timeout(Duration::from_secs(30))
                    .send()
                    .await
                    .map(drop),
                None => Ok(()),
            },
            Self::ChallTestSrv { http, url } => http
                .post(format!("{url}/clear-txt"))
                .json(&json!({ "host": format!("{}.", record.name) }))
                .send()
                .await
                .map(drop),
        };
        if let Err(error) = result {
            warn!(%error, name = %record.name, "failed to delete a challenge record");
        }
    }
}

#[derive(Deserialize)]
struct DnsJson {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DnsAnswer>,
}

#[derive(Deserialize)]
struct DnsAnswer {
    #[serde(rename = "type")]
    kind: u32,
    data: String,
}

/// Waits until public resolvers (Cloudflare and Google over DNS-over-HTTPS) return every challenge value, or
/// `timeout` passes, after which issuance proceeds anyway, as the Worker did.
pub async fn wait_for_propagation(
    http: &reqwest::Client,
    records: &[TxtRecord],
    timeout: Duration,
) {
    if timeout.is_zero() || records.is_empty() {
        return;
    }
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut visible = true;
        for record in records {
            if !resolvers_see(http, record).await {
                visible = false;
                break;
            }
        }
        if visible {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            warn!("DNS challenge records were not visible before the propagation timeout");
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn resolvers_see(http: &reqwest::Client, record: &TxtRecord) -> bool {
    for resolver in [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ] {
        let Ok(mut url) = url::Url::parse(resolver) else {
            continue;
        };
        url.query_pairs_mut()
            .append_pair("name", &record.name)
            .append_pair("type", "TXT");
        let response = http
            .get(url)
            .header("accept", "application/dns-json")
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        let Ok(response) = response else { continue };
        let Ok(body) = response.json::<DnsJson>().await else {
            continue;
        };
        if body.status != 0 {
            continue;
        }
        if body
            .answer
            .iter()
            .filter(|answer| answer.kind == 16)
            .any(|answer| answer.data.trim_matches('"') == record.value)
        {
            return true;
        }
    }
    false
}
