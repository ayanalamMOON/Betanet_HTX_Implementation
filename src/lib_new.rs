//! HTX (Covert Transport) - Core networking library for Betanet
//!
//! This crate provides the core transport layer implementation for Betanet,
//! offering encrypted connections that appear as normal HTTPS traffic on port 443.
//!
//! ## Features
//!
//! - **Origin Mirroring**: Automatically calibrates TLS fingerprints to match target origins
//! - **Access Tickets**: Negotiated carrier authentication system
//! - **Noise XK**: Inner encryption layer with key separation and rekeying
//! - **Multiplexed Streams**: HTTP/2-style stream multiplexing with flow control
//! - **Dual Transport**: Support for both TCP-443 and QUIC-443
//! - **Anti-Correlation**: Built-in traffic analysis resistance
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use htx::{HtxClient, HtxServer, Config};
//!
//! #[tokio::main]
//! async fn main() -> htx::Result<()> {
//!     // Client usage
//!     let config = Config::default();
//!     let mut client = HtxClient::new(config).await?;
//!     let conn = client.dial("example.com:443").await?;
//!     let mut stream = conn.open_stream().await?;
//!
//!     // Server usage
//!     let mut server = HtxServer::bind("0.0.0.0:443", config).await?;
//!     while let Some(conn) = server.accept().await? {
//!         tokio::spawn(async move {
//!             // Handle connection
//!         });
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod access_ticket;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod flow_control;
pub mod frame;
pub mod noise;
pub mod origin_mirror;
pub mod protocol;
pub mod server;
pub mod stream;
pub mod tls;
pub mod transport;

// Re-export core types
pub use client::HtxClient;
pub use config::Config;
pub use error::{HtxError, Result};
pub use protocol::ProtocolVersion;
pub use server::HtxServer;
pub use transport::{HtxConnection, HtxStream};

/// HTX protocol version
pub const PROTOCOL_VERSION: &str = "1.1.0";

/// Default TCP port for HTX connections
pub const DEFAULT_TCP_PORT: u16 = 443;

/// Default QUIC port for HTX connections
pub const DEFAULT_QUIC_PORT: u16 = 443;

/// Maximum frame size (16MB)
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Flow control window size
pub const FLOW_CONTROL_WINDOW: u32 = 65535;
