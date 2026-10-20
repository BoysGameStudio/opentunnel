//! `/api/admin/*` on this server, behind the `ADMIN_TOKEN` bearer secret (404 without it):
//!
//! - `POST /api/admin/import[?force=1]`: imports an export file (a restore), refusing any record the server could
//!   not have written itself (`migration::check`)
//! - `POST /api/admin/export`: every record, in the same format, streamed a page at a time
//! - `POST /api/admin/stats`: tunnel, alarm and job counts, this machine's counters, and every machine's bridges

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use hyper::{Response, StatusCode};
use serde_json::json;

use crate::http::{Admin, App, Body, json_response, response};
use crate::migration::{self, ExportFile};

pub struct TokenAdmin {
    pub token_hash: String,
}

impl Admin for TokenAdmin {
    fn authorized(&self, token: &str) -> bool {
        !token.is_empty() && crate::crypto::token_matches(token, &self.token_hash)
    }

    fn handle(
        &self,
        app: Arc<App>,
        path: String,
        body: Bytes,
    ) -> BoxFuture<'static, Response<Body>> {
        async move {
            let service = &app.service;
            let (path, query) = path.split_once('?').unwrap_or((&path, ""));
            match path {
                "import" => {
                    let file: ExportFile = match serde_json::from_slice(&body) {
                        Ok(file) => file,
                        Err(error) => {
                            return json_response(
                                StatusCode::BAD_REQUEST,
                                &json!({ "error": error.to_string() }),
                            );
                        }
                    };
                    let force = query.split('&').any(|pair| pair == "force=1");
                    match migration::import(
                        &service.store,
                        &service.clock,
                        &service.domain.to_ascii_lowercase(),
                        file,
                        force,
                    )
                    .await
                    {
                        Ok(summary) => {
                            for id in &summary.ids {
                                service.invalidate(id).await;
                            }
                            json_response(StatusCode::OK, &summary)
                        }
                        Err(error) => json_response(
                            StatusCode::BAD_REQUEST,
                            &json!({ "error": format!("{error:#}") }),
                        ),
                    }
                }
                "export" => {
                    // Streamed as it is read, so neither PlanetScale's result limit nor Cloudflare's 100 s wait
                    // for a response applies to the whole table.
                    let chunks = migration::export(
                        service.store.clone(),
                        service.clock.clone(),
                        migration::EXPORT_PAGE,
                    );
                    let mut response = Response::new(crate::http::streamed(chunks));
                    response.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    response
                }
                "stats" => match service.store.counts().await {
                    Ok(mut counts) => {
                        // This machine's counters (top level, as before, and under `machine`).
                        let stats = &app.stats;
                        counts["bridges_attached"] = service.bridge_count().into();
                        counts["tunnel_connections"] =
                            stats.tunnel_connections.load(Ordering::Relaxed).into();
                        if let Some(cluster) = service.cluster() {
                            counts["machine"] = json!({
                                "id": cluster.machine_id,
                                "region": cluster.region,
                                "address": cluster.address(),
                                "bridges_attached": service.bridge_count(),
                                "tunnel_connections": stats.tunnel_connections.load(Ordering::Relaxed),
                                "forwarded_out": stats.forwarded_out.load(Ordering::Relaxed),
                                "forwarded_in": stats.forwarded_in.load(Ordering::Relaxed),
                                "forward_failures": stats.forward_failures.load(Ordering::Relaxed),
                                // Grows with open connections and bridges only; anything else is a leak.
                                "tasks": tokio::runtime::Handle::current().metrics().num_alive_tasks(),
                                // Open file descriptors: sockets, the database pool, and a few files.
                                "fds": crate::net::open_fds(),
                            });
                            // Every machine and link, from the mesh.
                            counts["cluster"] = cluster.view();
                        }
                        json_response(StatusCode::OK, &counts)
                    }
                    Err(error) => json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &json!({ "error": format!("{error:#}") }),
                    ),
                },
                _ => response(StatusCode::NOT_FOUND),
            }
        }
        .boxed()
    }
}
