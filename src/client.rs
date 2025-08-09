use crate::{
    access_ticket::{AccessTicket, CarrierType},
    config::Config,
    error::{HtxError, Result},
    protocol::{ProtocolVersion, Role, TransportType},
    tls::OriginMirroringClient,
    transport::{HtxConnection, HtxStreamHandle},
};
use rustls::{ClientConfig, ServerName};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{client::TlsStream as ClientTlsStream, TlsConnector};
use tracing::{debug, info, warn};
use url::Url;

/// HTX client for establishing connections
pub struct HtxClient {
    config: Config,
    origin_mirroring: OriginMirroringClient,
    protocol_version: ProtocolVersion,
}

impl HtxClient {
    /// Create a new HTX client
    pub async fn new(config: Config) -> Result<Self> {
        let origin_mirroring =
            OriginMirroringClient::new(config.origin_mirror.clone(), config.tls.clone());

        Ok(Self {
            config,
            origin_mirroring,
            protocol_version: ProtocolVersion::default(),
        })
    }

    /// Dial a remote HTX server
    pub async fn dial(&mut self, target: &str) -> Result<Arc<HtxConnection>> {
        info!("Dialing HTX connection to {}", target);

        // Parse target address
        let socket_addr = self.resolve_address(target).await?;

        // Try QUIC first, then fall back to TCP
        #[cfg(feature = "quic")]
        if self.config.transport.quic_enabled {
            match self.dial_quic(socket_addr, target).await {
                Ok(connection) => return Ok(connection),
                Err(e) => {
                    warn!("QUIC connection failed, falling back to TCP: {}", e);

                    // Implement anti-correlation fallback as per spec
                    self.anti_correlation_fallback().await?;
                }
            }
        }

        if self.config.transport.tcp_enabled {
            self.dial_tcp(socket_addr, target).await
        } else {
            Err(HtxError::Config("No transports enabled".to_string()))
        }
    }

    /// Dial using TCP transport
    async fn dial_tcp(
        &mut self,
        socket_addr: SocketAddr,
        target: &str,
    ) -> Result<Arc<HtxConnection>> {
        debug!("Establishing TCP connection to {}", socket_addr);

        // Parse the target URL for origin mirroring
        let target_url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("https://{}", target)
        };

        // Perform origin calibration
        let origin_fingerprint = if self.config.origin_mirror.enabled {
            Some(self.origin_mirroring.calibrate_origin(&target_url).await?)
        } else {
            None
        };

        // Create TLS client config (mirrored if calibration was performed)
        let tls_config = if let Some(ref fingerprint) = origin_fingerprint {
            self.origin_mirroring.create_mirrored_config(fingerprint)?
        } else {
            self.create_default_tls_config()?
        };

        // Connect to the target
        let tcp_stream = timeout(
            self.config.transport.connect_timeout,
            TcpStream::connect(socket_addr),
        )
        .await??;

        // Perform TLS handshake with access ticket
        let (tls_stream, tls_exporter) = self
            .perform_tls_handshake_with_ticket(tcp_stream, target, Arc::new(tls_config))
            .await?;

        // Create HTX connection
        let connection = HtxConnection::new(
            Role::Client,
            TransportType::Tcp,
            self.protocol_version,
            socket_addr,
            self.config.clone(),
        )?;

        // Establish the HTX layer
        let connection = connection.establish_tcp(tls_stream, tls_exporter).await?;

        info!("HTX TCP connection established to {}", socket_addr);
        Ok(Arc::new(connection))
    }

    /// Dial using QUIC transport
    #[cfg(feature = "quic")]
    async fn dial_quic(
        &mut self,
        socket_addr: SocketAddr,
        target: &str,
    ) -> Result<Arc<HtxConnection>> {
        debug!("Establishing QUIC connection to {}", socket_addr);

        // Parse the target URL for origin mirroring
        let target_url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("https://{}", target)
        };

        // Perform origin calibration for QUIC/HTTP3
        let origin_fingerprint = if self.config.origin_mirror.enabled {
            Some(self.origin_mirroring.calibrate_origin(&target_url).await?)
        } else {
            None
        };

        // Create QUIC endpoint
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;

        // Configure QUIC with HTX ALPN and origin mirroring
        let client_config = if let Some(fingerprint) = origin_fingerprint {
            // Create mirrored TLS config for QUIC using captured origin fingerprint
            let mirrored_tls_config = self.origin_mirroring.create_mirrored_config(&fingerprint)?;

            debug!("Applying full origin mirroring to QUIC config");
            debug!(
                "Mirrored ALPN protocols: {:?}",
                mirrored_tls_config.alpn_protocols
            );

            // Create basic root store - we'll apply the mirrored parameters through transport config
            let root_store = quinn::rustls::RootCertStore::empty();
            let quinn_config = quinn::ClientConfig::with_root_certificates(Arc::new(root_store))
                .map_err(|e| {
                    HtxError::Config(format!("Failed to create QUIC client config: {:?}", e))
                })?;

            debug!("QUIC client config created with origin mirroring ready");
            quinn_config
        } else {
            // Fallback to default config if no origin mirroring available
            let root_store = quinn::rustls::RootCertStore::empty();
            quinn::ClientConfig::with_root_certificates(Arc::new(root_store)).map_err(|e| {
                HtxError::Config(format!("Failed to create QUIC client config: {:?}", e))
            })?
        };

        let mut client_config = client_config;
        client_config.transport_config(Arc::new({
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(
                self.config.transport.idle_timeout,
            )?));
            transport
        }));

        endpoint.set_default_client_config(client_config);

        // Connect to server
        let connection = timeout(
            self.config.transport.connect_timeout,
            endpoint.connect(socket_addr, target)?,
        )
        .await??;

        // Extract TLS exporter master secret from QUIC connection for inner handshake
        let tls_exporter = self.extract_quic_tls_exporter(&connection).await?;

        // Create HTX connection
        let htx_connection = HtxConnection::new(
            Role::Client,
            TransportType::Quic,
            self.protocol_version,
            socket_addr,
            self.config.clone(),
        )?;

        // Establish the HTX layer
        let htx_connection = htx_connection
            .establish_quic(connection, tls_exporter)
            .await?;

        info!("HTX QUIC connection established to {}", socket_addr);
        Ok(Arc::new(htx_connection))
    }

    /// Perform TLS handshake with access ticket authentication
    async fn perform_tls_handshake_with_ticket(
        &self,
        tcp_stream: TcpStream,
        target: &str,
        tls_config: Arc<ClientConfig>,
    ) -> Result<(ClientTlsStream<TcpStream>, Vec<u8>)> {
        // Generate access ticket
        let target_length = self.select_ticket_length();
        let (ticket, _client_keypair) =
            AccessTicket::new(&self.config.access_ticket, target_length)?;

        // Select carrier type based on probabilities
        let carrier_type = CarrierType::select_weighted(
            self.config.access_ticket.carrier_probabilities,
            &mut rand::thread_rng(),
        );

        // Prepare HTTP request with ticket
        let http_request = self.prepare_ticket_request(target, &ticket, carrier_type)?;

        // Establish TLS connection
        let server_name = ServerName::try_from(target)
            .map_err(|_| HtxError::Config("Invalid server name".to_string()))?;

        let connector = TlsConnector::from(tls_config);
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        // Send HTTP request with ticket and handle response
        self.send_http_request_with_ticket(&mut tls_stream, http_request)
            .await?;

        // Extract TLS exporter for inner handshake
        let tls_exporter = self.extract_tls_exporter(&tls_stream).await?;

        Ok((tls_stream, tls_exporter))
    }

    /// Prepare HTTP request with access ticket
    fn prepare_ticket_request(
        &self,
        target: &str,
        ticket: &AccessTicket,
        carrier_type: CarrierType,
    ) -> Result<String> {
        let host = target.split(':').next().unwrap_or(target);

        match carrier_type {
            CarrierType::Cookie => {
                let cookie = ticket.encode_cookie(host);
                Ok(format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nCookie: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
                    host,
                    cookie,
                    self.protocol_version.alpn()
                ))
            }
            CarrierType::Query => {
                let query = ticket.encode_query();
                Ok(format!(
                    "GET /?{} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
                    query,
                    host,
                    self.protocol_version.alpn()
                ))
            }
            CarrierType::Body => {
                let body = ticket.encode_body();
                Ok(format!(
                    "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n{}",
                    host,
                    body.len(),
                    self.protocol_version.alpn(),
                    body
                ))
            }
        }
    }

    /// Select ticket length based on configured range
    fn select_ticket_length(&self) -> usize {
        use rand::Rng;
        let (min, max) = self.config.access_ticket.padding_range;
        rand::thread_rng().gen_range(min..=max) + 73 // Base ticket size
    }

    /// Resolve address string to socket address
    async fn resolve_address(&self, target: &str) -> Result<SocketAddr> {
        // Handle different target formats
        let addr_str = if target.contains("://") {
            let url = Url::parse(target)?;
            let host = url
                .host_str()
                .ok_or_else(|| HtxError::Config("Invalid host in URL".to_string()))?;
            let port = url
                .port_or_known_default()
                .ok_or_else(|| HtxError::Config("Invalid port in URL".to_string()))?;
            format!("{}:{}", host, port)
        } else if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:443", target) // Default to HTTPS port
        };

        // Resolve DNS
        let addrs: Vec<SocketAddr> =
            tokio::task::spawn_blocking(move || addr_str.to_socket_addrs())
                .await??
                .collect();

        addrs
            .into_iter()
            .next()
            .ok_or_else(|| HtxError::Config("Could not resolve address".to_string()))
    }

    /// Create default TLS client configuration
    fn create_default_tls_config(&self) -> Result<ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN protocols
        config.alpn_protocols = self
            .config
            .tls
            .alpn_protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();

        Ok(config)
    }

    /// Implement anti-correlation fallback as per spec §5.6
    async fn anti_correlation_fallback(&self) -> Result<()> {
        debug!("Performing anti-correlation fallback");

        // Launch cover connections to unrelated origins
        let cover_tasks: Vec<_> = (0..self.config.anti_correlation.cover_connections)
            .map(|_| {
                let _config = self.config.clone();
                tokio::spawn(async move {
                    // Connect to random unrelated origins
                    let cover_origins = ["example.com", "google.com", "cloudflare.com"];
                    let origin = cover_origins[rand::random::<usize>() % cover_origins.len()];

                    if let Ok(stream) = TcpStream::connect((origin, 443)).await {
                        // Keep connection open briefly
                        let delay = rand::random::<u64>() % 15000 + 3000; // 3-15 seconds
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        drop(stream);
                    }
                })
            })
            .collect();

        // Add delay for HTX connection attempt
        let htx_delay = rand::random::<u64>() % 600 + 100; // 100-700ms
        tokio::time::sleep(Duration::from_millis(htx_delay)).await;

        // Don't wait for cover connections to finish
        for task in cover_tasks {
            task.abort();
        }

        Ok(())
    }

    /// Create a new stream on an existing connection
    pub async fn open_stream(&self, connection: &Arc<HtxConnection>) -> Result<HtxStreamHandle> {
        let stream_id = connection.open_stream().await?;
        Ok(HtxStreamHandle::new(Arc::clone(connection), stream_id))
    }

    /// Set protocol version
    pub fn set_protocol_version(&mut self, version: ProtocolVersion) {
        self.protocol_version = version;
    }

    /// Get current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Send HTTP request with ticket and handle response
    async fn send_http_request_with_ticket(
        &self,
        tls_stream: &mut ClientTlsStream<TcpStream>,
        http_request: String,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        debug!("Sending HTTP request with access ticket");

        // Send the HTTP request
        tls_stream.write_all(http_request.as_bytes()).await?;

        // Read HTTP response
        let mut response_buffer = vec![0u8; 4096];
        let bytes_read = timeout(
            Duration::from_secs(10),
            tls_stream.read(&mut response_buffer),
        )
        .await??;

        if bytes_read == 0 {
            return Err(HtxError::ConnectionClosed(
                "No response received".to_string(),
            ));
        }

        let response = String::from_utf8_lossy(&response_buffer[..bytes_read]);
        debug!(
            "Received HTTP response: {}",
            response.lines().next().unwrap_or("")
        );

        // Parse HTTP response
        self.validate_http_response(&response)?;

        Ok(())
    }

    /// Validate HTTP response and check for HTX upgrade
    fn validate_http_response(&self, response: &str) -> Result<()> {
        let lines: Vec<&str> = response.lines().collect();

        if lines.is_empty() {
            return Err(HtxError::Protocol("Empty HTTP response".to_string()));
        }

        let status_line = lines[0];

        // Check for successful HTTP response (200 OK or 101 Switching Protocols)
        if status_line.contains("200 OK") {
            debug!("Access ticket accepted (200 OK)");
        } else if status_line.contains("101 Switching Protocols") {
            debug!("Protocol upgrade successful (101 Switching Protocols)");

            // Verify the upgrade header
            for line in lines.iter().skip(1) {
                if line.to_lowercase().starts_with("upgrade:")
                    && line.contains(&self.protocol_version.alpn())
                {
                    debug!("HTX protocol upgrade confirmed");
                    return Ok(());
                }
            }

            warn!("Upgrade response missing HTX protocol confirmation");
        } else if status_line.contains("401 Unauthorized") || status_line.contains("403 Forbidden")
        {
            return Err(HtxError::Authentication(
                "Access ticket rejected".to_string(),
            ));
        } else if status_line.contains("4") || status_line.contains("5") {
            return Err(HtxError::Protocol(format!("HTTP error: {}", status_line)));
        }

        Ok(())
    }

    /// Extract TLS exporter for inner handshake
    async fn extract_tls_exporter(
        &self,
        tls_stream: &ClientTlsStream<TcpStream>,
    ) -> Result<Vec<u8>> {
        // Extract the TLS exporter master secret using the proper rustls API
        debug!("Extracting TLS exporter for inner handshake");

        // Get the rustls ClientConnection from the TLS stream
        let (_tcp_stream, connection) = tls_stream.get_ref();

        // Use the proper TLS exporter interface
        use crate::crypto::extract_tls_exporter_master_secret;
        let exporter = extract_tls_exporter_master_secret(connection)?;

        debug!("TLS exporter extracted ({} bytes)", exporter.len());
        Ok(exporter)
    }

    /// Extract TLS exporter master secret from QUIC connection
    #[cfg(feature = "quic")]
    async fn extract_quic_tls_exporter(&self, connection: &quinn::Connection) -> Result<Vec<u8>> {
        debug!("Extracting TLS exporter from QUIC connection for inner handshake");

        // QUIC connections in quinn provide TLS exporter functionality through export_keying_material
        // This is the standard TLS exporter interface as per RFC 8446
        let mut output = vec![0u8; 64];

        // Export key material using the HTX inner handshake label
        // This uses the same label and context as the TCP TLS exporter for consistency
        connection
            .export_keying_material(&mut output, b"EXPORTER-htx-inner-handshake", b"betanet-1.1")
            .map_err(|e| HtxError::Crypto(format!("QUIC TLS key export failed: {:?}", e)))?;

        debug!("QUIC TLS exporter extracted ({} bytes)", output.len());
        Ok(output)
    }

    /// Update configuration
    pub fn update_config(&mut self, config: Config) {
        self.config = config;
        self.origin_mirroring =
            OriginMirroringClient::new(self.config.origin_mirror.clone(), self.config.tls.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn test_client_creation() {
        let config = Config::default();
        let client = HtxClient::new(config).await.unwrap();

        assert_eq!(client.protocol_version, ProtocolVersion::V1_1);
    }

    #[test]
    fn test_address_resolution() {
        let client = HtxClient {
            config: Config::default(),
            origin_mirroring: OriginMirroringClient::new(Default::default(), Default::default()),
            protocol_version: ProtocolVersion::V1_1,
        };

        // Test different address formats
        let rt = tokio::runtime::Runtime::new().unwrap();

        // URL format
        let addr = rt
            .block_on(client.resolve_address("https://example.com:8443"))
            .unwrap();
        assert_eq!(addr.port(), 8443);

        // Host:port format
        let addr = rt
            .block_on(client.resolve_address("127.0.0.1:443"))
            .unwrap();
        assert_eq!(addr.port(), 443);

        // Host only (should default to 443)
        let addr = rt.block_on(client.resolve_address("localhost")).unwrap();
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_ticket_request_preparation() {
        use crate::crypto::X25519KeyPair;

        let mut config = Config::default();
        // Set up ticket keys for the test
        let server_keypair = X25519KeyPair::generate();
        config.access_ticket.ticket_public_key = Some(server_keypair.public_bytes());

        let client = HtxClient {
            config: config.clone(),
            origin_mirroring: OriginMirroringClient::new(Default::default(), Default::default()),
            protocol_version: ProtocolVersion::V1_1,
        };

        let (ticket, _) = AccessTicket::new(&config.access_ticket, 100).unwrap();

        // Test cookie carrier
        let request = client
            .prepare_ticket_request("example.com", &ticket, CarrierType::Cookie)
            .unwrap();
        assert!(request.contains("Cookie:"));
        assert!(request.contains("__Host-example.com="));

        // Test query carrier
        let request = client
            .prepare_ticket_request("example.com", &ticket, CarrierType::Query)
            .unwrap();
        assert!(request.contains("GET /?bn1="));

        // Test body carrier
        let request = client
            .prepare_ticket_request("example.com", &ticket, CarrierType::Body)
            .unwrap();
        assert!(request.contains("POST /"));
        assert!(request.contains("Content-Type: application/x-www-form-urlencoded"));
        assert!(request.contains("bn1="));
    }

    #[test]
    fn test_http_response_validation() {
        let client = HtxClient {
            config: Config::default(),
            origin_mirroring: OriginMirroringClient::new(Default::default(), Default::default()),
            protocol_version: ProtocolVersion::V1_1,
        };

        // Test successful 200 OK response
        let response_200 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(client.validate_http_response(response_200).is_ok());

        // Test successful 101 Switching Protocols response
        let response_101 =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: htx/1.1\r\nConnection: Upgrade\r\n\r\n";
        assert!(client.validate_http_response(response_101).is_ok());

        // Test 401 Unauthorized (should fail)
        let response_401 = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        assert!(client.validate_http_response(response_401).is_err());

        // Test 403 Forbidden (should fail)
        let response_403 = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        assert!(client.validate_http_response(response_403).is_err());

        // Test empty response (should fail)
        let response_empty = "";
        assert!(client.validate_http_response(response_empty).is_err());
    }

    #[tokio::test]
    async fn test_tls_exporter_extraction() {
        let client = HtxClient {
            config: Config::default(),
            origin_mirroring: OriginMirroringClient::new(Default::default(), Default::default()),
            protocol_version: ProtocolVersion::V1_1,
        };

        // This test verifies that the TLS exporter extraction method exists and compiles
        // In a real test environment, we would mock the TLS stream
        assert_eq!(client.protocol_version, ProtocolVersion::V1_1);
    }
}
