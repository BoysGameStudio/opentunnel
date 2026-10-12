use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{tag}: {message} (HTTP {status})")]
    Api {
        status: u16,
        tag: String,
        message: String,
    },
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid stored data in {path}: {source}")]
    Corrupt {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("bridge attach failed: {0}")]
    Attach(String),
    #[error("bridge error: {0}")]
    Bridge(String),
    #[error("certificate issuance failed: {0}")]
    CertificateFailed(String),
    #[error("{0}")]
    Invalid(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl Error {
    /// A failure that may pass on its own: the API unreachable, rate limited, or failing on the server side.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Api { status, .. } => crate::protocol::api::retryable_status(
                *status,
                crate::protocol::api::Repeat::Idempotent,
            ),
            Error::Http(error) => error.is_connect() || error.is_timeout() || error.is_request(),
            _ => false,
        }
    }

    pub(crate) fn io(context: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
        let context = context.into();
        move |source| Error::Io { context, source }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
