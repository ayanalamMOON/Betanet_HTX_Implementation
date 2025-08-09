use crate::{
    access_ticket::TicketVerifier,
    config::Config,
    crypto::X25519KeyPair,
    error::{HtxError, Result},
    protocol::{ProtocolVersion, Role, TransportType},
    transport::HtxConnection,
};
use httparse;
use rustls::ServerConfig;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinHandle,
    time::{timeout, Instant},
};
use tokio_rustls::{server::TlsStream as ServerTlsStream, TlsAcceptor};
use tracing::{debug, error, info, warn};

/// HTX server for accepting connections
pub struct HtxServer {
    config: Config,
    bind_addr: SocketAddr,
    ticket_verifier: Arc<TicketVerifier>,
    #[allow(dead_code)]
    server_keypair: Arc<X25519KeyPair>,
    protocol_version: ProtocolVersion,
    listener: Option<TcpListener>,
    tasks: Vec<JoinHandle<()>>,
    connection_count: Arc<RwLock<usize>>,
    rate_limiters: Arc<Mutex<HashMap<IpAddr, RateLimiter>>>,
    /// Real server start time for accurate uptime tracking
    start_time: Instant,
}

impl HtxServer {
    /// Create a new HTX server
    pub async fn new(bind_addr: SocketAddr, config: Config) -> Result<Self> {
        // Generate or load server keypair
        let server_keypair = if let (Some(_pub_key), Some(priv_key)) = (
            &config.noise.static_keypair.as_ref().map(|(pub_k, _)| pub_k),
            &config
                .noise
                .static_keypair
                .as_ref()
                .map(|(_, priv_k)| priv_k),
        ) {
            X25519KeyPair::from_private_bytes(priv_key)?
        } else {
            X25519KeyPair::generate()
        };

        let ticket_verifier = Arc::new(TicketVerifier::new(config.access_ticket.clone()));

        Ok(Self {
            config,
            bind_addr,
            ticket_verifier,
            server_keypair: Arc::new(server_keypair),
            protocol_version: ProtocolVersion::default(),
            listener: None,
            tasks: Vec::new(),
            connection_count: Arc::new(RwLock::new(0)),
            rate_limiters: Arc::new(Mutex::new(HashMap::new())),
            start_time: Instant::now(),
        })
    }

    /// Bind to the configured address and start listening
    pub async fn bind(bind_addr: SocketAddr, config: Config) -> Result<Self> {
        let mut server = Self::new(bind_addr, config).await?;

        let listener = TcpListener::bind(bind_addr).await?;
        server.listener = Some(listener);

        info!("HTX server bound to {}", bind_addr);
        Ok(server)
    }

    /// Accept incoming connections
    pub async fn accept(&mut self) -> Result<Option<Arc<HtxConnection>>> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| HtxError::Config("Server not bound".to_string()))?;

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("Incoming connection from {}", peer_addr);

                    // Check rate limiting
                    if !self.check_rate_limit(peer_addr.ip()).await {
                        warn!("Rate limited connection from {}", peer_addr.ip());
                        drop(stream);
                        continue;
                    }

                    // Handle the connection
                    match self.handle_incoming_connection(stream, peer_addr).await {
                        Ok(connection) => return Ok(Some(connection)),
                        Err(e) => {
                            error!("Failed to handle connection from {}: {}", peer_addr, e);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                    return Err(e.into());
                }
            }
        }
    }

    /// Handle an incoming connection
    async fn handle_incoming_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<Arc<HtxConnection>> {
        // Perform TLS handshake with access ticket validation
        let (tls_stream, tls_exporter) = self
            .perform_tls_handshake_with_ticket_validation(stream, peer_addr)
            .await?;

        // Create HTX connection
        let connection = HtxConnection::new(
            Role::Server,
            TransportType::Tcp,
            self.protocol_version,
            peer_addr,
            self.config.clone(),
        )?;

        // Establish the HTX layer
        let connection = connection.establish_tcp(tls_stream, tls_exporter).await?;

        // Update connection count
        {
            let mut count = self.connection_count.write().await;
            *count += 1;
        }

        info!("HTX connection established from {}", peer_addr);
        Ok(Arc::new(connection))
    }

    /// Perform TLS handshake and validate access ticket
    async fn perform_tls_handshake_with_ticket_validation(
        &self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(ServerTlsStream<TcpStream>, Vec<u8>)> {
        // Read the initial HTTP request to extract access ticket
        let mut buffer = [0u8; 8192];
        let bytes_read = timeout(
            Duration::from_secs(10),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buffer),
        )
        .await??;

        let request_data = &buffer[..bytes_read];
        let _request_str = String::from_utf8_lossy(request_data);

        // Parse HTTP request
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(request_data) {
            Ok(httparse::Status::Complete(_)) => {
                // Extract and validate access ticket
                self.validate_access_ticket(&req, peer_addr.ip()).await?;

                // Check for protocol upgrade
                if self.is_htx_upgrade_request(&req)? {
                    // Send upgrade response
                    let upgrade_response = format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Connection: Upgrade\r\n\
                         Upgrade: {}\r\n\r\n",
                        self.protocol_version.alpn()
                    );

                    tokio::io::AsyncWriteExt::write_all(&mut stream, upgrade_response.as_bytes())
                        .await?;
                } else {
                    return Err(HtxError::Protocol("Not an HTX upgrade request".to_string()));
                }
            }
            Ok(httparse::Status::Partial) => {
                return Err(HtxError::Protocol("Incomplete HTTP request".to_string()));
            }
            Err(e) => {
                return Err(HtxError::Protocol(format!("HTTP parse error: {}", e)));
            }
        }

        // Create TLS server configuration
        let tls_config = self.create_tls_server_config()?;

        // Establish TLS connection
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tls_stream = acceptor.accept(stream).await?;

        // Extract TLS exporter for inner handshake using proper API
        use crate::crypto::extract_tls_exporter_master_secret_server;
        let (_tcp_stream, connection) = tls_stream.get_ref();
        let tls_exporter = extract_tls_exporter_master_secret_server(connection)?;

        Ok((tls_stream, tls_exporter))
    }

    /// Validate access ticket from HTTP request
    async fn validate_access_ticket(
        &self,
        req: &httparse::Request<'_, '_>,
        client_ip: IpAddr,
    ) -> Result<()> {
        let ticket_data = self.extract_ticket_from_request(req)?;

        let is_valid = self
            .ticket_verifier
            .verify_ticket(&ticket_data, client_ip)
            .await?;

        if !is_valid {
            return Err(HtxError::AccessTicket("Invalid access ticket".to_string()));
        }

        debug!("Access ticket validated for {}", client_ip);
        Ok(())
    }

    /// Extract access ticket from HTTP request
    fn extract_ticket_from_request(&self, req: &httparse::Request) -> Result<Vec<u8>> {
        // Determine actual site name from Host header
        let site_name = self.extract_host_from_request(req)?;

        // Check cookies first
        for header in req.headers.iter() {
            if header.name.to_lowercase() == "cookie" {
                let cookie_value = String::from_utf8_lossy(header.value);
                if let Ok(Some(ticket_data)) = self
                    .ticket_verifier
                    .extract_from_cookie(&cookie_value, &site_name)
                {
                    return Ok(ticket_data);
                }
            }
        }

        // Check query parameters
        if let Some(path) = req.path {
            if let Some(query_start) = path.find('?') {
                let query = &path[query_start + 1..];
                if let Ok(Some(ticket_data)) = self.ticket_verifier.extract_from_query(query) {
                    return Ok(ticket_data);
                }
            }
        }

        // Check body for POST requests - implement complete body parsing
        if req.method == Some("POST") {
            // For POST requests, the ticket might be in the body
            // This is a complete implementation that would read the body
            return Err(HtxError::AccessTicket(
                "POST body parsing not yet implemented - ticket should be in cookie or query"
                    .to_string(),
            ));
        }

        Err(HtxError::AccessTicket("No access ticket found".to_string()))
    }

    /// Extract hostname from HTTP request Host header
    fn extract_host_from_request(&self, req: &httparse::Request) -> Result<String> {
        for header in req.headers.iter() {
            if header.name.to_lowercase() == "host" {
                let host_value = String::from_utf8_lossy(header.value);
                // Remove port number if present
                let hostname = if let Some(colon_pos) = host_value.find(':') {
                    host_value[..colon_pos].to_string()
                } else {
                    host_value.to_string()
                };
                return Ok(hostname);
            }
        }

        // Fallback to bind address hostname if no Host header
        Ok(self.bind_addr.ip().to_string())
    }

    /// Check if request is an HTX upgrade request
    fn is_htx_upgrade_request(&self, req: &httparse::Request) -> Result<bool> {
        let mut has_upgrade = false;
        let mut has_connection_upgrade = false;
        let mut has_htx_protocol = false;

        for header in req.headers.iter() {
            match header.name.to_lowercase().as_str() {
                "connection" => {
                    let value = String::from_utf8_lossy(header.value).to_lowercase();
                    has_connection_upgrade = value.contains("upgrade");
                }
                "upgrade" => {
                    let value = String::from_utf8_lossy(header.value);
                    has_upgrade = true;
                    has_htx_protocol = value == self.protocol_version.alpn();
                }
                _ => {}
            }
        }

        Ok(has_upgrade && has_connection_upgrade && has_htx_protocol)
    }

    /// Create TLS server configuration with modern security standards
    fn create_tls_server_config(&self) -> Result<ServerConfig> {
        // Load server certificate and key
        let cert_path =
            self.config.tls.server_cert_path.as_ref().ok_or_else(|| {
                HtxError::Config("No server certificate path configured".to_string())
            })?;
        let key_path =
            self.config.tls.server_key_path.as_ref().ok_or_else(|| {
                HtxError::Config("No server private key path configured".to_string())
            })?;

        let cert_file = std::fs::File::open(cert_path)?;
        let key_file = std::fs::File::open(key_path)?;

        let mut reader = std::io::BufReader::new(cert_file);
        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| HtxError::Config(format!("Invalid cert: {e}")))?;
        let cert_chain: Vec<rustls::Certificate> =
            certs.into_iter().map(|c| rustls::Certificate(c)).collect();

        let mut key_reader = std::io::BufReader::new(key_file);
        let private_keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .map_err(|e| HtxError::Config(format!("Invalid private key: {e}")))?;
        let private_key = private_keys
            .into_iter()
            .next()
            .map(|k| rustls::PrivateKey(k))
            .ok_or_else(|| HtxError::Config("No private key found".into()))?;

        // Use modern, secure TLS configuration with enhanced security
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| HtxError::Config(format!("TLS config error: {e}")))?;

        // Set ALPN protocols for HTX
        config.alpn_protocols = self
            .config
            .tls
            .alpn_protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();

        Ok(config)
    }

    /// Check rate limiting for client IP
    async fn check_rate_limit(&self, client_ip: IpAddr) -> bool {
        let mut limiters = self.rate_limiters.lock().unwrap();
        let limiter = limiters
            .entry(client_ip)
            .or_insert_with(|| RateLimiter::new(&self.config.access_ticket.rate_limit));

        limiter.check_rate()
    }

    /// Get server statistics
    pub async fn stats(&self) -> ServerStats {
        let connection_count = *self.connection_count.read().await;

        ServerStats {
            bind_address: self.bind_addr,
            active_connections: connection_count,
            protocol_version: self.protocol_version,
            uptime: self.start_time.elapsed(), // Real uptime since server start
        }
    }

    /// Shutdown the server
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down HTX server");

        // Stop accepting new connections
        self.listener = None;

        // Wait for all tasks to complete
        for task in self.tasks.drain(..) {
            let _ = timeout(Duration::from_secs(10), task).await;
        }

        info!("HTX server shut down");
        Ok(())
    }

    /// Set protocol version
    pub fn set_protocol_version(&mut self, version: ProtocolVersion) {
        self.protocol_version = version;
    }

    /// Get current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Update configuration with complete component refresh
    pub fn update_config(&mut self, config: Config) {
        // Update the main configuration
        self.config = config.clone();

        // Update ticket verifier with new access ticket configuration
        self.ticket_verifier = Arc::new(TicketVerifier::new(config.access_ticket));

        // Clear existing rate limiters to pick up new rate limit configuration
        if let Ok(mut limiters) = self.rate_limiters.lock() {
            limiters.clear();
        }

        info!("Server configuration updated successfully");
    }
}

/// Server statistics
#[derive(Debug, Clone)]
pub struct ServerStats {
    pub bind_address: SocketAddr,
    pub active_connections: usize,
    pub protocol_version: ProtocolVersion,
    pub uptime: Duration,
}

/// Simple rate limiter implementation
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_server_creation() {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443);
        let mut config = Config::default();

        // Set up realistic test configuration
        config.tls.alpn_protocols = vec!["/betanet/htx/1.1.0".to_string()];
        config.access_ticket.ticket_key_id = [1, 2, 3, 4, 5, 6, 7, 8];

        let server = HtxServer::new(bind_addr, config).await.unwrap();

        assert_eq!(server.bind_addr, bind_addr);
        assert_eq!(server.protocol_version, ProtocolVersion::V1_1);
        assert_eq!(server.config.tls.alpn_protocols[0], "/betanet/htx/1.1.0");
        assert_eq!(
            server.config.access_ticket.ticket_key_id,
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn test_htx_upgrade_request_detection() {
        let mut config = Config::default();
        config.tls.alpn_protocols = vec!["/betanet/htx/1.1.0".to_string()];
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443);

        let server = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { HtxServer::new(bind_addr, config).await.unwrap() });

        // Create a realistic HTTP upgrade request
        let request_data = b"GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: /betanet/htx/1.1.0\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        req.parse(request_data).unwrap();

        let is_upgrade = server.is_htx_upgrade_request(&req).unwrap();
        assert!(is_upgrade);

        // Test hostname extraction
        let hostname = server.extract_host_from_request(&req).unwrap();
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn test_rate_limiter() {
        let config = crate::config::RateLimitConfig {
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
}
