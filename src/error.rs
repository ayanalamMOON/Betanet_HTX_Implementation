use thiserror::Error;
use tokio::time::error::Elapsed;
use tokio::task::JoinError;
#[cfg(feature = "quic")]
use quinn::{ConnectError, VarIntBoundsExceeded};

/// Core HTX error types
#[derive(Error, Debug)]
pub enum HtxError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[cfg(feature = "quic")]
    #[error("QUIC error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[cfg(feature = "quic")]
    #[error("QUIC connect error: {0}")]
    QuicConnect(#[from] ConnectError),
    #[cfg(feature = "quic")]
    #[error("QUIC varint error: {0}")]
    QuicVarInt(#[from] VarIntBoundsExceeded),

    #[error("Noise protocol error: {0}")]
    Noise(#[from] snow::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol violation: {0}")]
    Protocol(String),

    #[error("Invalid frame type: {0}")]
    InvalidFrame(u8),

    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Access ticket verification failed: {0}")]
    AccessTicket(String),

    #[error("Origin calibration failed: {0}")]
    OriginCalibration(String),

    #[error("Flow control violation: {0}")]
    FlowControl(String),

    #[error("Key update error: {0}")]
    KeyUpdate(String),

    #[error("Connection closed: {0}")]
    ConnectionClosed(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("Deserialization error: {0}")]
    Deserialization(#[from] ciborium::de::Error<std::io::Error>),

    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),

    #[error("HTTP/2 error: {0}")]
    Http2(#[from] h2::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Timeout: {0}")]
    TokioTimeout(#[from] Elapsed),

    #[error("Join error: {0}")]
    Join(#[from] JoinError),
}

/// Result type alias for HTX operations
pub type Result<T> = std::result::Result<T, HtxError>;

/// Connection-specific error types
#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Protocol version mismatch")]
    VersionMismatch,

    #[error("Connection aborted: {0}")]
    Aborted(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Rate limited")]
    RateLimited,
}

/// Stream-specific error types
#[derive(Error, Debug)]
pub enum StreamError {
    #[error("Stream closed")]
    Closed,

    #[error("Stream reset: {0}")]
    Reset(u32),

    #[error("Flow control exceeded")]
    FlowControlExceeded,

    #[error("Stream ID conflict")]
    IdConflict,

    #[error("Invalid stream state")]
    InvalidState,
}

impl From<ConnectionError> for HtxError {
    fn from(err: ConnectionError) -> Self {
        HtxError::Protocol(err.to_string())
    }
}

impl From<StreamError> for HtxError {
    fn from(err: StreamError) -> Self {
        HtxError::Stream(err.to_string())
    }
}
