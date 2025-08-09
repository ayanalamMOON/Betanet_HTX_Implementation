use serde::{Deserialize, Serialize};
use std::fmt;

// =============================
// Protocol Version
// =============================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolVersion {
    /// Version 1.0 (legacy compatibility)
    V1_0,
    /// Version 1.1 (current)
    V1_1,
}

impl ProtocolVersion {
    /// Get the ALPN string for this protocol version
    pub fn alpn(&self) -> &'static str {
        match self {
            ProtocolVersion::V1_0 => "/betanet/htx/1.0.0",
            ProtocolVersion::V1_1 => "/betanet/htx/1.1.0",
        }
    }

    /// Get the QUIC ALPN string for this protocol version
    pub fn quic_alpn(&self) -> &'static str {
        match self {
            ProtocolVersion::V1_0 => "/betanet/htxquic/1.0.0",
            ProtocolVersion::V1_1 => "/betanet/htxquic/1.1.0",
        }
    }

    /// Parse from ALPN string
    pub fn from_alpn(alpn: &str) -> Option<Self> {
        match alpn {
            "/betanet/htx/1.0.0" | "/betanet/htxquic/1.0.0" => Some(ProtocolVersion::V1_0),
            "/betanet/htx/1.1.0" | "/betanet/htxquic/1.1.0" => Some(ProtocolVersion::V1_1),
            _ => None,
        }
    }

    /// Check if this version supports post-quantum cryptography
    pub fn supports_post_quantum(&self) -> bool {
        match self {
            ProtocolVersion::V1_0 => false,
            ProtocolVersion::V1_1 => true,
        }
    }

    /// Check if this version requires post-quantum cryptography after 2027-01-01
    pub fn requires_post_quantum(&self, current_time: chrono::DateTime<chrono::Utc>) -> bool {
        if !self.supports_post_quantum() {
            return false;
        }

        let pq_deadline = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        current_time >= pq_deadline
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion::V1_1
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolVersion::V1_0 => write!(f, "1.0"),
            ProtocolVersion::V1_1 => write!(f, "1.1"),
        }
    }
}

// =============================
// Transport Type
// =============================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    /// TCP transport on port 443
    Tcp,
    /// QUIC transport on UDP port 443 (behind feature flag)
    #[cfg(feature = "quic")]
    Quic,
    /// WebRTC transport (placeholder – not yet implemented)
    WebRtc,
}

impl TransportType {
    /// Get the default port for this transport
    pub fn default_port(&self) -> u16 {
        match self {
            TransportType::Tcp => 443,
            #[cfg(feature = "quic")]
            TransportType::Quic => 443,
            TransportType::WebRtc => 443,
        }
    }

    /// Check if this transport uses UDP
    pub fn is_udp(&self) -> bool {
        #[cfg(feature = "quic")]
        {
            matches!(self, TransportType::Quic | TransportType::WebRtc)
        }
        #[cfg(not(feature = "quic"))]
        {
            matches!(self, TransportType::WebRtc)
        }
    }

    /// Check if this transport uses TCP
    pub fn is_tcp(&self) -> bool {
        matches!(self, TransportType::Tcp)
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Tcp => write!(f, "tcp"),
            #[cfg(feature = "quic")]
            TransportType::Quic => write!(f, "quic"),
            TransportType::WebRtc => write!(f, "webrtc"),
        }
    }
}

/// Connection role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Client (initiator)
    Client,
    /// Server (responder)
    Server,
}

/// Privacy mode for mixnet routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyMode {
    /// Every stream through ≥ 3 Nym hops
    Strict,
    /// ≥ 2 hops until peer-trust ≥ 0.8 (default)
    Balanced,
    /// No mixnet unless destination label .mixreq
    Performance,
}

impl Default for PrivacyMode {
    fn default() -> Self {
        PrivacyMode::Balanced
    }
}

impl fmt::Display for PrivacyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyMode::Strict => write!(f, "strict"),
            PrivacyMode::Balanced => write!(f, "balanced"),
            PrivacyMode::Performance => write!(f, "performance"),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// Initial state
    Idle,
    /// TLS handshake in progress
    TlsHandshake,
    /// Access ticket validation in progress
    AccessTicketValidation,
    /// Noise handshake in progress
    NoiseHandshake,
    /// Connection established and ready
    Established,
    /// Connection closing
    Closing,
    /// Connection closed
    Closed,
    /// Connection error
    Error,
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamState {
    /// Stream idle (not yet opened)
    Idle,
    /// Stream open and ready
    Open,
    /// Stream half-closed (local)
    HalfClosedLocal,
    /// Stream half-closed (remote)
    HalfClosedRemote,
    /// Stream fully closed
    Closed,
    /// Stream reset
    Reset,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_alpn() {
        assert_eq!(ProtocolVersion::V1_0.alpn(), "/betanet/htx/1.0.0");
        assert_eq!(ProtocolVersion::V1_1.alpn(), "/betanet/htx/1.1.0");
        assert_eq!(ProtocolVersion::V1_0.quic_alpn(), "/betanet/htxquic/1.0.0");
        assert_eq!(ProtocolVersion::V1_1.quic_alpn(), "/betanet/htxquic/1.1.0");
    }

    #[test]
    fn test_protocol_version_from_alpn() {
        assert_eq!(
            ProtocolVersion::from_alpn("/betanet/htx/1.0.0"),
            Some(ProtocolVersion::V1_0)
        );
        assert_eq!(
            ProtocolVersion::from_alpn("/betanet/htx/1.1.0"),
            Some(ProtocolVersion::V1_1)
        );
        assert_eq!(ProtocolVersion::from_alpn("invalid"), None);
    }

    #[test]
    fn test_post_quantum_requirements() {
        let before_deadline = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let after_deadline = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:01Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert!(!ProtocolVersion::V1_0.supports_post_quantum());
        assert!(ProtocolVersion::V1_1.supports_post_quantum());

        assert!(!ProtocolVersion::V1_1.requires_post_quantum(before_deadline));
        assert!(ProtocolVersion::V1_1.requires_post_quantum(after_deadline));
    }

    #[test]
    fn test_transport_type_tcp() {
        assert_eq!(TransportType::Tcp.default_port(), 443);
        assert!(TransportType::Tcp.is_tcp());
        assert!(!TransportType::Tcp.is_udp());
    }

    #[cfg(feature = "quic")]
    #[test]
    fn test_transport_type_quic() {
        assert_eq!(TransportType::Quic.default_port(), 443);
        assert!(TransportType::Quic.is_udp());
        assert!(!TransportType::Quic.is_tcp());
    }
}
