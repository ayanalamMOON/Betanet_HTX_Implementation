use crate::{
    config::AccessTicketConfig,
    crypto::{access_ticket, random_bytes, X25519KeyPair},
    error::{HtxError, Result},
};
use base64::{engine::general_purpose, Engine as _};
use bytes::BufMut;
use rand::Rng;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant; // for gen_range

/// Access ticket carrier types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierType {
    Cookie,
    Query,
    Body,
}

impl CarrierType {
    /// Select carrier based on probabilities
    pub fn select_weighted(probabilities: (f64, f64, f64), rng: &mut impl rand::RngCore) -> Self {
        let (cookie_prob, query_prob, body_prob) = probabilities;
        let total = cookie_prob + query_prob + body_prob;
        let r: f64 = rng.gen_range(0.0..total);

        if r < cookie_prob {
            CarrierType::Cookie
        } else if r < cookie_prob + query_prob {
            CarrierType::Query
        } else {
            CarrierType::Body
        }
    }
}

/// Access ticket structure
#[derive(Debug, Clone)]
pub struct AccessTicket {
    pub version: u8,
    pub cli_pub: [u8; 32],
    pub ticket_key_id: [u8; 8],
    pub nonce: [u8; 32],
    pub ticket: [u8; 32],
    pub padding: Vec<u8>,
}

impl AccessTicket {
    /// Create a new access ticket
    pub fn new(config: &AccessTicketConfig, target_length: usize) -> Result<(Self, X25519KeyPair)> {
        let cli_keypair = X25519KeyPair::generate();
        let nonce = {
            let mut n = [0u8; 32];
            n.copy_from_slice(&random_bytes(32));
            n
        };

        // Get current hour
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| HtxError::Crypto(format!("Time error: {}", e)))?;
        let hour = now.as_secs() / 3600;

        // Generate ticket
        let ticket_pub = config
            .ticket_public_key
            .ok_or_else(|| HtxError::Config("No ticket public key configured".to_string()))?;

        let ticket = access_ticket::generate_ticket(
            &cli_keypair.private_bytes(),
            &ticket_pub,
            &config.ticket_key_id,
            &nonce,
            hour,
        )?;

        // Calculate required padding
        let base_size = 1 + 32 + 8 + 32 + 32; // version + cli_pub + key_id + nonce + ticket
        let padding_needed = if target_length > base_size {
            target_length - base_size
        } else {
            0
        };

        let padding = random_bytes(padding_needed);

        Ok((
            Self {
                version: 0x01,
                cli_pub: cli_keypair.public_bytes(),
                ticket_key_id: config.ticket_key_id,
                nonce,
                ticket,
                padding,
            },
            cli_keypair,
        ))
    }

    /// Serialize the ticket for transport
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.put_u8(self.version);
        buf.put_slice(&self.cli_pub);
        buf.put_slice(&self.ticket_key_id);
        buf.put_slice(&self.nonce);
        buf.put_slice(&self.ticket);
        buf.put_slice(&self.padding);
        buf
    }

    /// Deserialize a ticket from bytes
    pub fn deserialize(mut data: &[u8]) -> Result<Self> {
        if data.len() < 73 {
            // minimum size: 1 + 32 + 8 + 32 + 32
            return Err(HtxError::AccessTicket("Ticket too short".to_string()));
        }

        let version = data[0];
        data = &data[1..];

        if version != 0x01 {
            return Err(HtxError::AccessTicket("Invalid ticket version".to_string()));
        }

        let mut cli_pub = [0u8; 32];
        cli_pub.copy_from_slice(&data[..32]);
        data = &data[32..];

        let mut ticket_key_id = [0u8; 8];
        ticket_key_id.copy_from_slice(&data[..8]);
        data = &data[8..];

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[..32]);
        data = &data[32..];

        let mut ticket = [0u8; 32];
        ticket.copy_from_slice(&data[..32]);
        data = &data[32..];

        let padding = data.to_vec();

        Ok(Self {
            version,
            cli_pub,
            ticket_key_id,
            nonce,
            ticket,
            padding,
        })
    }

    /// Encode ticket for cookie carrier
    pub fn encode_cookie(&self, site_name: &str) -> String {
        let serialized = self.serialize();
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&serialized);
        format!("__Host-{site_name}={encoded}")
    }

    /// Encode ticket for query parameter carrier
    pub fn encode_query(&self) -> String {
        let serialized = self.serialize();
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&serialized);
        format!("bn1={}", encoded)
    }

    /// Encode ticket for body carrier
    pub fn encode_body(&self) -> String {
        let serialized = self.serialize();
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&serialized);
        format!("bn1={}", encoded)
    }
}

/// Access ticket verification state
pub struct TicketVerifier {
    config: AccessTicketConfig,
    seen_tickets: Arc<Mutex<HashMap<([u8; 32], u64), Instant>>>, // (cli_pub, hour) -> timestamp
    rate_limiters: Arc<Mutex<HashMap<IpAddr, RateLimiter>>>,
}

impl TicketVerifier {
    pub fn new(config: AccessTicketConfig) -> Self {
        Self {
            config,
            seen_tickets: Arc::new(Mutex::new(HashMap::new())),
            rate_limiters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Verify an access ticket
    pub async fn verify_ticket(&self, ticket_data: &[u8], client_ip: IpAddr) -> Result<bool> {
        // Check rate limit first
        if !self.check_rate_limit(client_ip).await? {
            return Ok(false);
        }

        // Parse ticket
        let ticket = AccessTicket::deserialize(ticket_data)?;

        // Validate padding range
        if ticket.padding.len() < self.config.padding_range.0
            || ticket.padding.len() > self.config.padding_range.1
        {
            return Ok(false);
        }

        // Get current time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| HtxError::Crypto(format!("Time error: {}", e)))?;
        let current_hour = now.as_secs() / 3600;

        // Check all valid hours (current, previous, next)
        for hour_offset in [-1i64, 0i64, 1i64] {
            let check_hour = (current_hour as i64 + hour_offset) as u64;

            // Check for replay
            let replay_key = (ticket.cli_pub, check_hour);
            {
                let seen = self.seen_tickets.lock().unwrap();
                if seen.contains_key(&replay_key) {
                    continue; // Already seen, try next hour
                }
            }

            // Verify ticket for this hour
            let ticket_priv = self
                .config
                .ticket_private_key
                .ok_or_else(|| HtxError::Config("No ticket private key configured".to_string()))?;

            let is_valid = access_ticket::verify_ticket(
                &ticket.cli_pub,
                &ticket_priv,
                &ticket.ticket_key_id,
                &ticket.ticket,
                check_hour,
            )?;

            if is_valid {
                // Mark as seen for 2 hours
                let mut seen = self.seen_tickets.lock().unwrap();
                seen.insert(replay_key, Instant::now());

                // Clean old entries (older than 2 hours)
                let cutoff = Instant::now() - Duration::from_secs(7200);
                seen.retain(|_, timestamp| *timestamp > cutoff);

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check rate limit for client IP
    async fn check_rate_limit(&self, client_ip: IpAddr) -> Result<bool> {
        let subnet_ip = self.get_subnet_ip(client_ip);

        let mut limiters = self.rate_limiters.lock().unwrap();
        let limiter = limiters
            .entry(subnet_ip)
            .or_insert_with(|| RateLimiter::new(&self.config.rate_limit));

        Ok(limiter.check_rate())
    }

    /// Get subnet IP for rate limiting
    fn get_subnet_ip(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(ipv4) => {
                let mask = self.config.rate_limit.ipv4_subnet_mask;
                let octets = ipv4.octets();
                let subnet_octets = apply_ipv4_mask(octets, mask);
                IpAddr::V4(subnet_octets.into())
            }
            IpAddr::V6(ipv6) => {
                let mask = self.config.rate_limit.ipv6_subnet_mask;
                let segments = ipv6.segments();
                let subnet_segments = apply_ipv6_mask(segments, mask);
                IpAddr::V6(subnet_segments.into())
            }
        }
    }

    /// Extract ticket from HTTP cookie
    pub fn extract_from_cookie(
        &self,
        cookie_header: &str,
        site_name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let prefix = format!("__Host-{site_name}=");

        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix(&prefix) {
                let decoded = general_purpose::URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|e| HtxError::Base64(e))?;
                return Ok(Some(decoded));
            }
        }

        Ok(None)
    }

    /// Extract ticket from query parameter
    pub fn extract_from_query(&self, query: &str) -> Result<Option<Vec<u8>>> {
        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                if key == "bn1" {
                    let decoded = general_purpose::URL_SAFE_NO_PAD
                        .decode(value)
                        .map_err(|e| HtxError::Base64(e))?;
                    return Ok(Some(decoded));
                }
            }
        }

        Ok(None)
    }

    /// Extract ticket from form body
    pub fn extract_from_body(&self, body: &str, content_type: &str) -> Result<Option<Vec<u8>>> {
        if content_type != "application/x-www-form-urlencoded" {
            return Ok(None);
        }

        self.extract_from_query(body) // Same format as query string
    }
}

/// Simple token bucket rate limiter
struct RateLimiter {
    tokens: f64,
    last_refill: Instant,
    max_tokens: f64,
    refill_rate: f64,
    refill_interval: Duration,
}

impl RateLimiter {
    fn new(config: &crate::config::RateLimitConfig) -> Self {
        Self {
            tokens: config.burst_size as f64,
            last_refill: Instant::now(),
            max_tokens: config.burst_size as f64,
            refill_rate: config.requests_per_second as f64,
            refill_interval: config.refill_interval,
        }
    }

    fn check_rate(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed >= self.refill_interval {
            let intervals = elapsed.as_secs_f64() / self.refill_interval.as_secs_f64();
            let tokens_to_add = self.refill_rate * intervals;
            self.tokens = (self.tokens + tokens_to_add).min(self.max_tokens);
            self.last_refill = now;
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Apply IPv4 subnet mask
fn apply_ipv4_mask(octets: [u8; 4], mask_bits: u8) -> [u8; 4] {
    if mask_bits >= 32 {
        return octets;
    }

    let mask = !((1u32 << (32 - mask_bits)) - 1);
    let addr = u32::from_be_bytes(octets);
    let subnet_addr = addr & mask;
    subnet_addr.to_be_bytes()
}

/// Apply IPv6 subnet mask
fn apply_ipv6_mask(segments: [u16; 8], mask_bits: u8) -> [u16; 8] {
    if mask_bits >= 128 {
        return segments;
    }

    let mut result = [0u16; 8];
    let full_segments = (mask_bits / 16) as usize;
    let remaining_bits = mask_bits % 16;

    // Copy full segments
    for i in 0..full_segments.min(8) {
        result[i] = segments[i];
    }

    // Handle partial segment
    if full_segments < 8 && remaining_bits > 0 {
        let mask = !((1u16 << (16 - remaining_bits)) - 1);
        result[full_segments] = segments[full_segments] & mask;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;

    #[test]
    fn test_access_ticket_creation() {
        let mut config = AccessTicketConfig::default();
        let keypair = X25519KeyPair::generate();
        config.ticket_public_key = Some(keypair.public_bytes());
        config.ticket_private_key = Some(keypair.private_bytes());

        let (ticket, _client_keypair) = AccessTicket::new(&config, 100).unwrap();

        assert_eq!(ticket.version, 0x01);
        assert_eq!(ticket.ticket_key_id, config.ticket_key_id);

        // Test serialization round-trip
        let serialized = ticket.serialize();
        let deserialized = AccessTicket::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, ticket.version);
        assert_eq!(deserialized.cli_pub, ticket.cli_pub);
        assert_eq!(deserialized.ticket_key_id, ticket.ticket_key_id);
        assert_eq!(deserialized.nonce, ticket.nonce);
        assert_eq!(deserialized.ticket, ticket.ticket);
        assert_eq!(deserialized.padding, ticket.padding);
    }

    #[test]
    fn test_carrier_encoding() {
        let mut config = AccessTicketConfig::default();
        let keypair = X25519KeyPair::generate();
        config.ticket_public_key = Some(keypair.public_bytes());
        config.ticket_private_key = Some(keypair.private_bytes());

        let (ticket, _) = AccessTicket::new(&config, 100).unwrap();

        // Test cookie encoding
        let cookie = ticket.encode_cookie("example");
        assert!(cookie.starts_with("__Host-example="));

        // Test query encoding
        let query = ticket.encode_query();
        assert!(query.starts_with("bn1="));

        // Test body encoding
        let body = ticket.encode_body();
        assert!(body.starts_with("bn1="));
    }

    #[test]
    fn test_rate_limiter() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 5,
            ipv4_subnet_mask: 24,
            ipv6_subnet_mask: 56,
            refill_interval: Duration::from_millis(100),
        };

        let mut limiter = RateLimiter::new(&config);

        // Should allow burst
        for _ in 0..5 {
            assert!(limiter.check_rate());
        }

        // Should deny after burst
        assert!(!limiter.check_rate());
    }

    #[test]
    fn test_ipv4_subnet_mask() {
        let octets = [192, 168, 1, 100];
        let result = apply_ipv4_mask(octets, 24);
        assert_eq!(result, [192, 168, 1, 0]);

        let result = apply_ipv4_mask(octets, 16);
        assert_eq!(result, [192, 168, 0, 0]);
    }
}
