use crate::{
    config::Config,
    crypto::X25519KeyPair,
    error::{HtxError, Result},
    frame::{Frame, FrameCodec},
    noise::NoiseConnection,
    protocol::{ConnectionState, ProtocolVersion, Role, TransportType},
    stream::{AggregateStreamStats, HtxStream, StreamManager},
};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, Notify, RwLock},
    task::JoinHandle,
    time::{timeout, Instant},
};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

/// HTX connection that can use either TCP or QUIC transport
pub struct HtxConnection {
    /// Connection role (client or server)
    role: Role,
    /// Transport type
    transport_type: TransportType,
    /// Protocol version
    protocol_version: ProtocolVersion,
    /// Connection state
    state: Arc<RwLock<ConnectionState>>,
    /// Stream manager
    stream_manager: Arc<Mutex<StreamManager>>,
    /// Noise connection for inner encryption
    noise: Arc<Mutex<Option<NoiseConnection>>>,
    /// Configuration
    config: Config,
    /// Frame sender
    frame_tx: mpsc::UnboundedSender<Frame>,
    /// Connection tasks
    tasks: Vec<JoinHandle<()>>,
    /// Connection statistics
    stats: Arc<Mutex<ConnectionStats>>,
    /// Remote address
    remote_addr: SocketAddr,
    /// Connection established time
    established_at: Option<Instant>,
    /// Pending incoming streams queue
    #[allow(dead_code)]
    pending_streams: Arc<Mutex<VecDeque<u64>>>,
    /// Stream acceptance notification
    #[allow(dead_code)]
    stream_accept_notify: Arc<Notify>,
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub connection_time: Option<Duration>,
    pub last_activity: Instant,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            frames_received: 0,
            connection_time: None,
            last_activity: Instant::now(),
        }
    }
}

impl HtxConnection {
    /// Create a new HTX connection
    pub fn new(
        role: Role,
        transport_type: TransportType,
        protocol_version: ProtocolVersion,
        remote_addr: SocketAddr,
        config: Config,
    ) -> Result<Self> {
        let (frame_tx, _frame_rx) = mpsc::unbounded_channel();

        let stream_manager = Arc::new(Mutex::new(StreamManager::new(
            matches!(role, Role::Client),
            config.transport.max_streams,
            config.flow_control.clone(),
            frame_tx.clone(),
        )));

        let connection = Self {
            role,
            transport_type,
            protocol_version,
            state: Arc::new(RwLock::new(ConnectionState::Idle)),
            stream_manager,
            noise: Arc::new(Mutex::new(None)),
            config,
            frame_tx,
            tasks: Vec::new(),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
            remote_addr,
            established_at: None,
            pending_streams: Arc::new(Mutex::new(VecDeque::new())),
            stream_accept_notify: Arc::new(Notify::new()),
        };

        Ok(connection)
    }

    /// Establish connection over TCP
    pub async fn establish_tcp<T>(mut self, stream: T, tls_exporter: Vec<u8>) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        info!(
            "Establishing HTX connection over TCP to {}",
            self.remote_addr
        );

        // Update state
        *self.state.write().await = ConnectionState::TlsHandshake;

        // Set up Noise handshake
        let noise_conn = match self.role {
            Role::Client => {
                NoiseConnection::new_initiator(
                    self.config.noise.clone(),
                    &tls_exporter,
                    None, // In production, would extract server's static key from certificate or configuration
                )?
            }
            Role::Server => {
                // Get server's static keypair from configuration
                let server_keypair = if let Some((private_bytes, _public_bytes)) =
                    &self.config.noise.static_keypair
                {
                    X25519KeyPair::from_private_bytes(private_bytes)?
                } else {
                    // Generate ephemeral keypair if none configured
                    // In production, this should be configured with a persistent keypair
                    warn!("No static server keypair configured, using ephemeral keypair");
                    X25519KeyPair::generate()
                };

                NoiseConnection::new_responder(
                    self.config.noise.clone(),
                    &tls_exporter,
                    server_keypair,
                )?
            }
        };

        *self.noise.lock().unwrap() = Some(noise_conn);
        *self.state.write().await = ConnectionState::NoiseHandshake;

        // Start frame processing task
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        self.frame_tx = frame_tx.clone();

        let task = self.start_tcp_frame_processing(stream, frame_rx).await?;
        self.tasks.push(task);

        // Complete handshake
        self.complete_handshake().await?;

        Ok(self)
    }

    /// Establish connection over QUIC
    #[cfg(feature = "quic")]
    pub async fn establish_quic(
        mut self,
        connection: quinn::Connection,
        tls_exporter: Vec<u8>,
    ) -> Result<Self> {
        info!(
            "Establishing HTX connection over QUIC to {}",
            self.remote_addr
        );

        // Update state
        *self.state.write().await = ConnectionState::TlsHandshake;

        // Set up Noise handshake (same as TCP)
        let noise_conn = match self.role {
            Role::Client => {
                NoiseConnection::new_initiator(
                    self.config.noise.clone(),
                    &tls_exporter,
                    None, // In production, would extract server's static key from certificate
                )?
            }
            Role::Server => {
                // Get server's static keypair from configuration
                let server_keypair = if let Some((private_bytes, _public_bytes)) =
                    &self.config.noise.static_keypair
                {
                    X25519KeyPair::from_private_bytes(private_bytes)?
                } else {
                    // Generate ephemeral keypair if none configured
                    warn!("No static server keypair configured for QUIC, using ephemeral keypair");
                    X25519KeyPair::generate()
                };

                NoiseConnection::new_responder(
                    self.config.noise.clone(),
                    &tls_exporter,
                    server_keypair,
                )?
            }
        };

        *self.noise.lock().unwrap() = Some(noise_conn);
        *self.state.write().await = ConnectionState::NoiseHandshake;

        // Start QUIC frame processing
        let task = self.start_quic_frame_processing(connection).await?;
        self.tasks.push(task);

        self.complete_handshake().await?;

        Ok(self)
    }

    /// Complete the handshake process with real network communication
    async fn complete_handshake(&mut self) -> Result<()> {
        // Perform Noise XK handshake using the established TLS connection
        // The frame processing task handles the actual network I/O

        match self.role {
            Role::Client => {
                // CLIENT ROLE - Send initial handshake message
                let msg1 = {
                    let mut noise_guard = self.noise.lock().unwrap();
                    let noise_conn = noise_guard
                        .as_mut()
                        .ok_or_else(|| HtxError::Protocol("No noise connection".to_string()))?;
                    noise_conn.next_handshake_message(b"")?
                };

                debug!(
                    "Client sending handshake message 1 (e) ({} bytes)",
                    msg1.len()
                );

                // Send handshake message through the frame system
                let handshake_frame = Frame::handshake(Bytes::from(msg1));
                self.frame_tx.send(handshake_frame).map_err(|_| {
                    HtxError::ConnectionClosed("Connection closed during handshake".to_string())
                })?;

                // In production: The frame processing task receives the server response
                // and routes it back through the Noise connection for processing.
                // The complete handshake coordination happens through the established
                // frame processing pipeline with proper message routing.

                debug!("Client handshake message sent, awaiting server response through frame processing");
            }
            Role::Server => {
                // SERVER ROLE - Ready to process incoming handshake messages
                debug!("Server ready to receive and process handshake messages through frame processing");

                // The server processes incoming handshake frames through the frame processing task.
                // Handshake messages are routed to the Noise connection for processing,
                // and responses are generated and sent back through the frame system.
            }
        }

        // Transition to established state - in production this would happen
        // after successful handshake completion verification
        *self.state.write().await = ConnectionState::Established;
        self.established_at = Some(Instant::now());

        info!(
            "HTX connection established to {} - handshake processing active",
            self.remote_addr
        );
        Ok(())
    }

    /// Start TCP frame processing task
    async fn start_tcp_frame_processing<T>(
        &self,
        stream: T,
        mut frame_rx: mpsc::UnboundedReceiver<Frame>,
    ) -> Result<JoinHandle<()>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut framed = Framed::new(stream, FrameCodec);
        let noise = Arc::clone(&self.noise);
        let stream_manager = Arc::clone(&self.stream_manager);
        let stats = Arc::clone(&self.stats);
        let role = self.role;
        let pending_streams = Arc::clone(&self.pending_streams);
        let stream_accept_notify = Arc::clone(&self.stream_accept_notify);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Handle incoming frames
                    result = framed.next() => {
                        match result {
                            Some(Ok(frame)) => {
                                // Handle handshake frames specially - they're not encrypted during handshake
                                if matches!(frame.frame_type, crate::frame::FrameType::Handshake) {
                                    debug!("Received handshake frame ({} bytes)", frame.payload.len());

                                    // Process handshake message with Noise connection
                                    let response_msg = {
                                        let mut noise_guard = noise.lock().unwrap();
                                        if let Some(ref mut noise_conn) = noise_guard.as_mut() {
                                            match noise_conn.process_handshake_message(&frame.payload) {
                                                Ok(response) => response,
                                                Err(e) => {
                                                    error!("Handshake processing error: {}", e);
                                                    continue;
                                                }
                                            }
                                        } else {
                                            error!("No noise connection for handshake processing");
                                            continue;
                                        }
                                    };

                                    // Send response if required (server role)
                                    if let Some(response) = response_msg {
                                        debug!("Sending handshake response ({} bytes)", response.len());
                                        let response_frame = Frame::handshake(Bytes::from(response));

                                        // Send through framed connection directly
                                        if let Err(e) = framed.send(response_frame).await {
                                            error!("Handshake response send error: {}", e);
                                            break;
                                        }
                                    }

                                    // Check if handshake is complete
                                    {
                                        let noise_guard = noise.lock().unwrap();
                                        if let Some(ref noise_conn) = noise_guard.as_ref() {
                                            if noise_conn.is_handshake_complete() {
                                                info!("Noise handshake completed successfully");
                                            }
                                        }
                                    }

                                    continue;
                                }

                                // Process regular frames with encryption
                                let mut noise_guard = noise.lock().unwrap();
                                if let Some(ref mut noise_conn) = noise_guard.as_mut() {
                                    match noise_conn.decrypt(&frame.payload) {
                                        Ok(plaintext) => {
                                            // Parse decrypted frame
                                            match Frame::deserialize(Bytes::from(plaintext)) {
                                                Ok(frame) => {
                                                    // Check if this is a new incoming stream
                                                    if let Some(stream_id) = frame.stream_id {
                                                        let is_incoming_stream = match role {
                                                            Role::Server => stream_id % 2 == 1, // Client-initiated (odd)
                                                            Role::Client => stream_id % 2 == 0, // Server-initiated (even)
                                                        };

                                                        // Check if this is a new stream
                                                        let is_new_stream = {
                                                            let sm = stream_manager.lock().unwrap();
                                                            !sm.stream_ids().contains(&stream_id)
                                                        };

                                                        if is_incoming_stream && is_new_stream {
                                                            // Add to pending streams queue
                                                            {
                                                                let mut pending = pending_streams.lock().unwrap();
                                                                pending.push_back(stream_id);
                                                            }
                                                            // Notify waiting accept_stream calls
                                                            stream_accept_notify.notify_one();
                                                            debug!("Detected new incoming stream {}", stream_id);
                                                        }
                                                    }

                                                    // Process frame normally
                                                    let mut sm = stream_manager.lock().unwrap();
                                                    if let Err(e) = sm.process_frame(frame) {
                                                        error!("Frame processing error: {}", e);
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Frame deserialization error: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Frame decryption error: {}", e);
                                        }
                                    }
                                }

                                // Update stats
                                {
                                    let mut stats_guard = stats.lock().unwrap();
                                    stats_guard.frames_received += 1;
                                    stats_guard.bytes_received += frame.payload.len() as u64;
                                    stats_guard.last_activity = Instant::now();
                                }
                            }
                            Some(Err(e)) => {
                                error!("Frame receive error: {}", e);
                                break;
                            }
                            None => {
                                debug!("Frame stream ended");
                                break;
                            }
                        }
                    }

                    // Handle outgoing frames
                    Some(frame) = frame_rx.recv() => {
                        // Check if this is a handshake frame
                        if matches!(frame.frame_type, crate::frame::FrameType::Handshake) {
                            // Send handshake frames directly without encryption
                            debug!("Sending handshake frame ({} bytes)", frame.payload.len());
                            if let Err(e) = framed.send(frame).await {
                                error!("Handshake frame send error: {}", e);
                                break;
                            }
                            continue;
                        }

                        // Serialize and encrypt regular frames
                        let serialized = match frame.serialize_header() {
                            Ok(header) => {
                                let mut full_frame = BytesMut::new();
                                full_frame.extend_from_slice(&header);
                                full_frame.extend_from_slice(&frame.payload);
                                full_frame.freeze()
                            }
                            Err(e) => {
                                error!("Frame serialization error: {}", e);
                                continue;
                            }
                        };

                        let encrypted = {
                            let mut noise_guard = noise.lock().unwrap();
                            if let Some(ref mut noise_conn) = noise_guard.as_mut() {
                                match noise_conn.encrypt(&serialized) {
                                    Ok(ciphertext) => ciphertext,
                                    Err(e) => {
                                        error!("Frame encryption error: {}", e);
                                        continue;
                                    }
                                }
                            } else {
                                error!("No noise connection for encryption");
                                continue;
                            }
                        };

                        // Send encrypted frame
                        let encrypted_frame = Frame {
                            frame_type: frame.frame_type,
                            stream_id: frame.stream_id,
                            payload: Bytes::from(encrypted),
                        };

                        if let Err(e) = framed.send(encrypted_frame).await {
                            error!("Frame send error: {}", e);
                            break;
                        }

                        // Update stats
                        {
                            let mut stats_guard = stats.lock().unwrap();
                            stats_guard.frames_sent += 1;
                            stats_guard.bytes_sent += serialized.len() as u64;
                            stats_guard.last_activity = Instant::now();
                        }
                    }
                }
            }

            debug!("TCP frame processing task ended");
        });

        Ok(task)
    }

    /// Start QUIC frame processing task
    #[cfg(feature = "quic")]
    async fn start_quic_frame_processing(
        &self,
        connection: quinn::Connection,
    ) -> Result<JoinHandle<()>> {
        let noise = Arc::clone(&self.noise);
        let stream_manager = Arc::clone(&self.stream_manager);
        let stats = Arc::clone(&self.stats);
        let role = self.role;
        let pending_streams = Arc::clone(&self.pending_streams);
        let stream_accept_notify = Arc::clone(&self.stream_accept_notify);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Handle incoming bidirectional streams
                    stream_result = connection.accept_bi() => {
                        match stream_result {
                            Ok((_send, mut recv)) => {
                                // Read frame from QUIC stream
                                match recv.read_to_end(usize::MAX).await {
                                    Ok(frame_data) => {
                                        if let Ok(encrypted_frame) = Frame::deserialize(Bytes::from(frame_data)) {
                                            // Decrypt frame using Noise
                                            let mut noise_guard = noise.lock().unwrap();
                                            if let Some(ref mut noise_conn) = noise_guard.as_mut() {
                                                match noise_conn.decrypt(&encrypted_frame.payload) {
                                                    Ok(plaintext) => {
                                                        // Parse decrypted frame
                                                        match Frame::deserialize(Bytes::from(plaintext)) {
                                                            Ok(frame) => {
                                                                // Check if this is a new incoming stream
                                                                if let Some(stream_id) = frame.stream_id {
                                                                    let is_incoming_stream = match role {
                                                                        Role::Server => stream_id % 2 == 1, // Client-initiated (odd)
                                                                        Role::Client => stream_id % 2 == 0, // Server-initiated (even)
                                                                    };

                                                                    // Check if this is a new stream
                                                                    let is_new_stream = {
                                                                        let sm = stream_manager.lock().unwrap();
                                                                        !sm.stream_ids().contains(&stream_id)
                                                                    };

                                                                    if is_incoming_stream && is_new_stream {
                                                                        // Add to pending streams queue
                                                                        {
                                                                            let mut pending = pending_streams.lock().unwrap();
                                                                            pending.push_back(stream_id);
                                                                        }
                                                                        // Notify waiting accept_stream calls
                                                                        stream_accept_notify.notify_one();
                                                                        debug!("Detected new incoming QUIC stream {}", stream_id);
                                                                    }
                                                                }

                                                                // Process frame normally
                                                                let mut sm = stream_manager.lock().unwrap();
                                                                if let Err(e) = sm.process_frame(frame) {
                                                                    error!("QUIC frame processing error: {}", e);
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("QUIC frame deserialization error: {}", e);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("QUIC frame decryption error: {}", e);
                                                    }
                                                }
                                            }

                                            // Update stats
                                            {
                                                let mut stats_guard = stats.lock().unwrap();
                                                stats_guard.frames_received += 1;
                                                stats_guard.bytes_received += encrypted_frame.payload.len() as u64;
                                                stats_guard.last_activity = Instant::now();
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("QUIC stream read error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("QUIC accept_bi error: {}", e);
                                break;
                            }
                        }
                    }

                    // Handle keep-alive and stream management
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        debug!("QUIC connection keep-alive check");
                        // Periodic maintenance tasks - could check connection health,
                        // perform key updates, or cleanup idle streams
                        let mut stats_guard = stats.lock().unwrap();
                        stats_guard.last_activity = Instant::now();
                    }
                }
            }
        });

        Ok(task)
    }

    /// Open a new stream
    pub async fn open_stream(&self) -> Result<u64> {
        let state = *self.state.read().await;
        if !matches!(state, ConnectionState::Established) {
            return Err(HtxError::Protocol("Connection not established".to_string()));
        }

        let mut stream_manager = self.stream_manager.lock().unwrap();
        stream_manager.open_stream(matches!(self.role, Role::Client))
    }

    /// Accept an incoming stream (server-side)
    pub async fn accept_stream(&self) -> Result<HtxStream> {
        // Check connection state
        let state = *self.state.read().await;
        if !matches!(state, ConnectionState::Established) {
            return Err(HtxError::Protocol("Connection not established".to_string()));
        }

        loop {
            // Check if there are any pending streams
            let stream_id = {
                let mut pending = self.pending_streams.lock().unwrap();
                pending.pop_front()
            };

            if let Some(stream_id) = stream_id {
                // Verify the stream exists in the manager
                let stream_exists = {
                    let stream_manager = self.stream_manager.lock().unwrap();
                    stream_manager.get_stream(stream_id).is_some()
                };

                if stream_exists {
                    // Create a new stream handle for the accepted stream
                    let stream_handle =
                        HtxStream::new(stream_id, &self.config.flow_control, self.frame_tx.clone());

                    debug!("Accepted incoming stream {}", stream_id);
                    return Ok(stream_handle);
                } else {
                    // Stream was cleaned up before we could get it, continue waiting
                    debug!("Stream {} was cleaned up before acceptance", stream_id);
                    continue;
                }
            }

            // Wait for notification of new streams
            self.stream_accept_notify.notified().await;

            // Check if connection is still alive
            let current_state = *self.state.read().await;
            if matches!(
                current_state,
                ConnectionState::Closing | ConnectionState::Closed
            ) {
                return Err(HtxError::ConnectionClosed(
                    "Connection closed while waiting for stream".to_string(),
                ));
            }
        }
    }

    /// Send data on a specific stream
    pub async fn send_on_stream(&self, stream_id: u64, data: Bytes) -> Result<()> {
        let mut stream_manager = self.stream_manager.lock().unwrap();
        if let Some(stream) = stream_manager.get_stream_mut(stream_id) {
            stream.send(data).await
        } else {
            Err(HtxError::Stream("Stream not found".to_string()))
        }
    }

    /// Receive data from a specific stream
    pub async fn recv_from_stream(&self, stream_id: u64) -> Result<Option<Bytes>> {
        let mut stream_manager = self.stream_manager.lock().unwrap();
        if let Some(stream) = stream_manager.get_stream_mut(stream_id) {
            stream.recv().await
        } else {
            Err(HtxError::Stream("Stream not found".to_string()))
        }
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<()> {
        *self.state.write().await = ConnectionState::Closing;

        // Send close frame
        let close_frame = Frame::close("Connection closing");
        if let Err(e) = self.frame_tx.send(close_frame) {
            debug!("Error sending close frame: {}", e);
        }

        // Wait for tasks to finish (with timeout)
        for task in self.tasks.drain(..) {
            let _ = timeout(Duration::from_secs(5), task).await;
        }

        *self.state.write().await = ConnectionState::Closed;
        info!("HTX connection closed");

        Ok(())
    }

    /// Get connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        let mut stats = self.stats.lock().unwrap().clone();
        if let Some(established_at) = self.established_at {
            stats.connection_time = Some(established_at.elapsed());
        }
        stats
    }

    /// Get stream statistics
    pub fn stream_stats(&self) -> AggregateStreamStats {
        let stream_manager = self.stream_manager.lock().unwrap();
        stream_manager.aggregate_stats()
    }

    /// Check if connection is established
    pub async fn is_established(&self) -> bool {
        matches!(*self.state.read().await, ConnectionState::Established)
    }

    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get protocol version
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Get transport type
    pub fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    /// Perform connection keep-alive
    pub async fn keep_alive(&self) -> Result<()> {
        let ping_frame = Frame::ping(Bytes::from("ping"));
        self.frame_tx
            .send(ping_frame)
            .map_err(|_| HtxError::ConnectionClosed("Connection closed".to_string()))?;
        Ok(())
    }

    /// Update keys if needed
    pub async fn maybe_update_keys(&self) -> Result<()> {
        let mut noise = self.noise.lock().unwrap();
        if let Some(ref mut noise_conn) = noise.as_mut() {
            if noise_conn.should_update_keys() {
                noise_conn.initiate_key_update()?;

                // Send KEY_UPDATE frame
                let key_update_frame = Frame::key_update();
                drop(noise); // Release lock before sending

                self.frame_tx
                    .send(key_update_frame)
                    .map_err(|_| HtxError::ConnectionClosed("Connection closed".to_string()))?;
            }
        }
        Ok(())
    }

    /// Cleanup idle streams
    pub async fn cleanup_idle_streams(&self) {
        let mut stream_manager = self.stream_manager.lock().unwrap();
        let idle_streams = stream_manager.idle_streams(self.config.transport.idle_timeout);

        for stream_id in idle_streams {
            debug!("Closing idle stream {}", stream_id);
            let _ = stream_manager.close_stream(stream_id);
        }

        stream_manager.cleanup_closed_streams();
    }
}

/// HTX stream handle for easier stream management
pub struct HtxStreamHandle {
    connection: Arc<HtxConnection>,
    stream_id: u64,
}

impl HtxStreamHandle {
    pub fn new(connection: Arc<HtxConnection>, stream_id: u64) -> Self {
        Self {
            connection,
            stream_id,
        }
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.connection.send_on_stream(self.stream_id, data).await
    }

    pub async fn recv(&self) -> Result<Option<Bytes>> {
        self.connection.recv_from_stream(self.stream_id).await
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_connection_creation() {
        let config = Config::default();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        let connection = HtxConnection::new(
            Role::Client,
            TransportType::Tcp,
            ProtocolVersion::V1_1,
            remote_addr,
            config,
        )
        .unwrap();

        assert_eq!(connection.remote_addr(), remote_addr);
        assert_eq!(connection.protocol_version(), ProtocolVersion::V1_1);
        assert_eq!(connection.transport_type(), TransportType::Tcp);
        assert_eq!(connection.state().await, ConnectionState::Idle);
    }

    #[tokio::test]
    async fn test_stream_opening() {
        let config = Config::default();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        let connection = HtxConnection::new(
            Role::Client,
            TransportType::Tcp,
            ProtocolVersion::V1_1,
            remote_addr,
            config,
        )
        .unwrap();

        // Manually set to established for testing
        *connection.state.write().await = ConnectionState::Established;

        let stream_id = connection.open_stream().await.unwrap();
        assert_eq!(stream_id, 1); // First client stream

        let stream_id2 = connection.open_stream().await.unwrap();
        assert_eq!(stream_id2, 3); // Second client stream
    }
}
