use serde::{Deserialize, Serialize};
use std::time::Duration;

/// HTX configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// TLS configuration
    pub tls: TlsConfig,

    /// Noise protocol configuration
    pub noise: NoiseConfig,

    /// Transport configuration
    pub transport: TransportConfig,

    /// Flow control configuration
    pub flow_control: FlowControlConfig,

    /// Access ticket configuration
    pub access_ticket: AccessTicketConfig,

    /// Origin mirroring configuration
    pub origin_mirror: OriginMirrorConfig,

    /// Anti-correlation configuration
    pub anti_correlation: AntiCorrelationConfig,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable encrypted client hello (ECH)
    pub ech_enabled: bool,

    /// Root certificate store path
    pub root_store_path: Option<String>,

    /// Client certificate path
    pub client_cert_path: Option<String>,

    /// Client private key path
    pub client_key_path: Option<String>,

    /// Server certificate path
    pub server_cert_path: Option<String>,

    /// Server private key path
    pub server_key_path: Option<String>,

    /// Supported ALPN protocols
    pub alpn_protocols: Vec<String>,

    /// TLS session timeout
    pub session_timeout: Duration,

    /// Enable session resumption
    pub session_resumption: bool,
}

/// Noise protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseConfig {
    /// Static keypair for server identity
    pub static_keypair: Option<(Vec<u8>, Vec<u8>)>,

    /// Enable post-quantum hybrid mode
    pub post_quantum: bool,

    /// Key update intervals
    pub key_update_bytes: u64,
    pub key_update_frames: u32,
    pub key_update_time: Duration,
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Enable TCP transport
    pub tcp_enabled: bool,

    /// Enable QUIC transport
    pub quic_enabled: bool,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Idle timeout
    pub idle_timeout: Duration,

    /// Maximum concurrent streams per connection
    pub max_streams: u32,

    /// Keep-alive interval
    pub keep_alive: Duration,

    /// Maximum frame size
    pub max_frame_size: u32,
}

/// Flow control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowControlConfig {
    /// Initial window size
    pub initial_window_size: u32,

    /// Maximum window size
    pub max_window_size: u32,

    /// Window update threshold (percentage)
    pub update_threshold: f64,
}

/// Access ticket configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTicketConfig {
    /// Ticket public key for server
    pub ticket_public_key: Option<[u8; 32]>,

    /// Ticket private key for server
    pub ticket_private_key: Option<[u8; 32]>,

    /// Ticket key ID
    pub ticket_key_id: [u8; 8],

    /// Carrier probabilities (cookie, query, body)
    pub carrier_probabilities: (f64, f64, f64),

    /// Padding length range
    pub padding_range: (usize, usize),

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
}

/// Origin mirroring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginMirrorConfig {
    /// Enable origin mirroring
    pub enabled: bool,

    /// Calibration timeout
    pub calibration_timeout: Duration,

    /// JA3 tolerance settings
    pub ja3_tolerance: JA3Tolerance,

    /// HTTP/2 settings tolerance
    pub h2_settings_tolerance: f64,
}

/// Anti-correlation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCorrelationConfig {
    /// Number of cover connections
    pub cover_connections: u32,

    /// Cover connection delay range
    pub cover_delay_range: (Duration, Duration),

    /// Cover connection timeout range
    pub cover_timeout_range: (Duration, Duration),

    /// Maximum retries per minute
    pub max_retries_per_minute: u32,
}

/// JA3 tolerance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JA3Tolerance {
    /// ALPN must match exactly
    pub alpn_exact: bool,

    /// Extension order must match exactly
    pub extension_order_exact: bool,

    /// H2 settings tolerance percentage
    pub h2_settings_tolerance: f64,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per second per IP
    pub requests_per_second: u32,

    /// Burst size
    pub burst_size: u32,

    /// IPv4 subnet mask for rate limiting
    pub ipv4_subnet_mask: u8,

    /// IPv6 subnet mask for rate limiting
    pub ipv6_subnet_mask: u8,

    /// Token bucket refill interval
    pub refill_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tls: TlsConfig::default(),
            noise: NoiseConfig::default(),
            transport: TransportConfig::default(),
            flow_control: FlowControlConfig::default(),
            access_ticket: AccessTicketConfig::default(),
            origin_mirror: OriginMirrorConfig::default(),
            anti_correlation: AntiCorrelationConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ech_enabled: true,
            root_store_path: None,
            client_cert_path: None,
            client_key_path: None,
            server_cert_path: None,
            server_key_path: None,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            session_timeout: Duration::from_secs(3600),
            session_resumption: true,
        }
    }
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            static_keypair: None,
            post_quantum: false, // Will be required from 2027-01-01
            key_update_bytes: 8 * 1024 * 1024 * 1024, // 8 GiB
            key_update_frames: 65536, // 2^16 frames
            key_update_time: Duration::from_secs(3600), // 1 hour
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tcp_enabled: true,
            quic_enabled: true,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_streams: 1000,
            keep_alive: Duration::from_secs(30),
            max_frame_size: 16 * 1024 * 1024, // 16 MB
        }
    }
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            initial_window_size: 65535,
            max_window_size: 1024 * 1024,
            update_threshold: 0.5,
        }
    }
}

impl Default for AccessTicketConfig {
    fn default() -> Self {
        Self {
            ticket_public_key: None,
            ticket_private_key: None,
            ticket_key_id: [0u8; 8],
            carrier_probabilities: (0.5, 0.3, 0.2), // cookie, query, body
            padding_range: (24, 64),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Default for OriginMirrorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            calibration_timeout: Duration::from_secs(10),
            ja3_tolerance: JA3Tolerance::default(),
            h2_settings_tolerance: 0.15,
        }
    }
}

impl Default for AntiCorrelationConfig {
    fn default() -> Self {
        Self {
            cover_connections: 2,
            cover_delay_range: (Duration::from_millis(0), Duration::from_secs(1)),
            cover_timeout_range: (Duration::from_secs(3), Duration::from_secs(15)),
            max_retries_per_minute: 2,
        }
    }
}

impl Default for JA3Tolerance {
    fn default() -> Self {
        Self {
            alpn_exact: true,
            extension_order_exact: true,
            h2_settings_tolerance: 0.15,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            burst_size: 20,
            ipv4_subnet_mask: 24,
            ipv6_subnet_mask: 56,
            refill_interval: Duration::from_millis(100),
        }
    }
}
