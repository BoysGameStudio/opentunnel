use std::path::PathBuf;
use std::time::Duration;

use crate::protocol::api::CertificateState;
use reqwest::Url;
use tracing::warn;

use crate::api::Api;
use crate::error::{Error, Result};
use crate::identity::{Identity, PendingIdentity};
use crate::provision;
use crate::storage::Storage;
use crate::tls::Trust;
use crate::tunnel::{Routes, Tunnel};

const CERTIFICATE_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Whether a certificate expiring at `expiry` (ISO-8601) has expired; an unreadable date counts as expired.
fn expired(expiry: &str) -> bool {
    humantime::parse_rfc3339_weak(expiry)
        .map_or(true, |expiry| expiry <= std::time::SystemTime::now())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionStage {
    CreatingTunnel,
    GeneratingKey,
    GeneratingCsr,
    ResumingCertificate,
    RequestingCertificate,
    WaitingCertificate,
    SavingIdentity,
    Ready,
}

#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    /// API base URL. Defaults to `https://opentunnel.xyz`.
    pub api: Option<Url>,
    /// Identity storage. Defaults to the XDG data directory.
    pub storage: Option<Storage>,
    /// PEM file of extra CA certificates to trust for the API and the
    /// bridge, besides the bundled and OS roots. Defaults to
    /// `OPENTUNNEL_CA_CERT`.
    pub ca_cert: Option<PathBuf>,
    /// Independent bearer credential sent only with the tunnel-creation API request.
    pub owner_token: Option<String>,
}

/// Creates, stores, and connects tunnels. Each profile owns one tunnel.
#[derive(Debug, Clone)]
pub struct Client {
    api: Api,
    storage: Storage,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(ClientOptions::default())
    }
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let api = options.api.unwrap_or_else(|| {
            Url::parse(crate::protocol::api::DEFAULT_API).expect("default API URL is valid")
        });
        Self {
            api: Api::with_trust(
                api,
                Trust::new(crate::tls::roots(options.ca_cert.as_deref())),
            )
            .with_owner_token(options.owner_token),
            storage: options.storage.unwrap_or_default(),
        }
    }

    pub fn api(&self) -> &Api {
        &self.api
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn profiles(&self) -> Result<Vec<String>> {
        self.storage.profiles()
    }

    pub fn list(&self) -> Result<Vec<(String, Identity)>> {
        self.storage.list()
    }

    pub fn get(&self, profile: &str) -> Result<Option<Identity>> {
        self.storage.load(profile)
    }

    pub fn pending(&self, profile: &str) -> Result<Option<PendingIdentity>> {
        self.storage.load_pending(profile)
    }

    /// Creates and provisions a tunnel for a profile that has none, resuming
    /// an interrupted provision when one is pending.
    pub async fn create(
        &self,
        profile: &str,
        progress: impl Fn(ProvisionStage),
    ) -> Result<Identity> {
        if self.storage.load(profile)?.is_some() {
            return Err(Error::Invalid(format!(
                "profile '{profile}' already has a tunnel"
            )));
        }
        if let Some(pending) = self.storage.load_pending(profile)? {
            progress(ProvisionStage::ResumingCertificate);
            return self.complete(profile, pending, &progress).await;
        }
        progress(ProvisionStage::CreatingTunnel);
        let created = self.api.create().await?;
        self.provision(
            profile,
            created.tunnel.id,
            created.tunnel.hostname,
            created.token,
            &progress,
        )
        .await
    }

    /// Finishes a pending provision, if any.
    pub async fn resume(
        &self,
        profile: &str,
        progress: impl Fn(ProvisionStage),
    ) -> Result<Option<Identity>> {
        let Some(pending) = self.storage.load_pending(profile)? else {
            return Ok(None);
        };
        progress(ProvisionStage::ResumingCertificate);
        self.complete(profile, pending, &progress).await.map(Some)
    }

    /// Returns the profile's tunnel, creating it or re-issuing a failed
    /// certificate as needed.
    pub async fn ensure(&self, profile: &str) -> Result<Identity> {
        let Some(existing) = self.storage.load(profile)? else {
            return self.create(profile, |_| {}).await;
        };
        let certificate = match self.api.certificate(&existing.token, &existing.id).await {
            Ok(certificate) => certificate,
            // The API is unreachable even after retries: a certificate that has not expired still serves, and a
            // running tunnel checks for a renewed one itself.
            Err(error) if error.is_transient() && !expired(&existing.certificate_expiry) => {
                warn!(%error, "could not check the certificate; using the saved one");
                return Ok(existing);
            }
            Err(error) => return Err(error),
        };
        match certificate.state {
            // The server renewed the certificate while this machine was offline.
            CertificateState::Ready {
                certificate,
                chain,
                expiry,
            } if certificate != existing.certificate => {
                let renewed = Identity {
                    certificate,
                    chain,
                    certificate_expiry: expiry,
                    ..existing
                };
                self.storage.save(profile, &renewed)?;
                return Ok(renewed);
            }
            CertificateState::Failed { .. } => {}
            _ => return Ok(existing),
        }
        self.provision(
            profile,
            existing.id,
            existing.hostname,
            existing.token,
            &|_| {},
        )
        .await
    }

    /// Deletes the tunnel on the server and removes local credentials.
    pub async fn remove(&self, profile: &str) -> Result<()> {
        if let Some(identity) = self.storage.load(profile)? {
            match self.api.remove(&identity.token, &identity.id).await {
                Ok(()) | Err(Error::Api { status: 404, .. }) => {}
                Err(error) => return Err(error),
            }
        }
        self.storage.remove(profile)
    }

    /// Starts forwarding the given routes for the profile's tunnel. Reconnects
    /// until closed and saves certificates the server renews.
    pub fn connect(&self, profile: &str, routes: Routes) -> Result<Tunnel> {
        let identity = self
            .storage
            .load(profile)?
            .ok_or_else(|| Error::Invalid(format!("profile '{profile}' has no tunnel")))?;
        Tunnel::start(
            self.api.clone(),
            identity,
            routes,
            Some((self.storage.clone(), profile.to_owned())),
        )
    }

    async fn provision(
        &self,
        profile: &str,
        id: String,
        hostname: String,
        token: String,
        progress: &impl Fn(ProvisionStage),
    ) -> Result<Identity> {
        progress(ProvisionStage::GeneratingKey);
        progress(ProvisionStage::GeneratingCsr);
        let generated = provision::generate(&hostname)?;
        let pending = PendingIdentity {
            id,
            hostname,
            token,
            private_key: generated.private_key,
            csr: generated.csr,
        };
        self.storage.save_pending(profile, &pending)?;
        self.complete(profile, pending, progress).await
    }

    async fn complete(
        &self,
        profile: &str,
        pending: PendingIdentity,
        progress: &impl Fn(ProvisionStage),
    ) -> Result<Identity> {
        progress(ProvisionStage::RequestingCertificate);
        match self
            .api
            .bind_certificate(&pending.token, &pending.id, &pending.csr)
            .await
        {
            Ok(_) => {}
            // A resumed provision may already have an issuance in flight.
            Err(Error::Api { tag, .. }) if tag == "CertificateInProgressError" => {}
            Err(error) => return Err(error),
        }
        let (certificate, chain, expiry) = loop {
            progress(ProvisionStage::WaitingCertificate);
            let info = self.api.certificate(&pending.token, &pending.id).await?;
            match info.state {
                CertificateState::Ready {
                    certificate,
                    chain,
                    expiry,
                } => break (certificate, chain, expiry),
                CertificateState::Failed { reason } => {
                    return Err(Error::CertificateFailed(reason));
                }
                CertificateState::Challenge { .. } | CertificateState::Issuing => {
                    tokio::time::sleep(CERTIFICATE_POLL_INTERVAL).await;
                }
            }
        };
        let identity = Identity {
            id: pending.id,
            hostname: pending.hostname,
            token: pending.token,
            private_key: pending.private_key,
            certificate,
            chain,
            certificate_expiry: expiry,
        };
        progress(ProvisionStage::SavingIdentity);
        self.storage.save(profile, &identity)?;
        progress(ProvisionStage::Ready);
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(api: &str) -> Client {
        let root = std::env::temp_dir().join(format!(
            "opentunnel-client-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let mut client = Client::new(ClientOptions {
            api: Some(Url::parse(api).unwrap()),
            storage: Some(Storage::at(root)),
            ..Default::default()
        });
        client.api.retry_scale = 1000;
        client
    }

    fn identity(expiry: &str) -> Identity {
        Identity {
            id: "demo".into(),
            hostname: "demo.test".into(),
            token: "token".into(),
            private_key: "key".into(),
            certificate: "certificate".into(),
            chain: String::new(),
            certificate_expiry: expiry.into(),
        }
    }

    #[tokio::test]
    async fn ensure_keeps_a_valid_certificate_while_the_api_is_unreachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = client(&api);

        client
            .storage
            .save("default", &identity("2099-01-01T00:00:00.000Z"))
            .unwrap();
        let ensured = client.ensure("default").await.unwrap();
        assert_eq!(ensured.certificate, "certificate");

        client
            .storage
            .save("default", &identity("2020-01-01T00:00:00.000Z"))
            .unwrap();
        assert!(client.ensure("default").await.is_err());
    }
}
