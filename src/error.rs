//! Error types for the tunnelbana core framework.

use thiserror::Error;

/// The result type used throughout the proxy.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type. Carries enough structure to be mapped onto an HTTP
/// response by the binary layer (see [`Error::status_hint`]).
#[derive(Debug, Error)]
pub enum Error {
    /// No registered endpoint matched the request path.
    #[error("no endpoint bound to path: {0}")]
    NoBoundEndpoint(String),

    /// A referenced frontend/backend/microservice name does not exist.
    #[error("unknown module: {0}")]
    UnknownModule(String),

    /// The request was malformed (missing params, bad encoding, etc.).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Authentication failed somewhere in the flow.
    #[error("authentication error: {0}")]
    Authn(String),

    /// State cookie could not be sealed/unsealed.
    #[error("state error: {0}")]
    State(String),

    /// Configuration is invalid or could not be loaded.
    #[error("configuration error: {0}")]
    Config(String),

    /// Cryptographic / key-material failure.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Attribute mapping failure.
    #[error("attribute mapping error: {0}")]
    Attribute(String),

    /// Wrapper around the JOSE library errors.
    #[error("jose error: {0}")]
    Jose(#[from] jose_rs::JoseError),

    /// JSON (de)serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Any other internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Suggested HTTP status code for surfacing this error to a client.
    pub fn status_hint(&self) -> u16 {
        match self {
            Error::NoBoundEndpoint(_) => 404,
            Error::BadRequest(_) => 400,
            Error::UnknownModule(_) => 404,
            Error::Authn(_) => 401,
            Error::Config(_) | Error::Crypto(_) | Error::State(_) => 500,
            _ => 500,
        }
    }
}
