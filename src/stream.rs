use crate::{
    config::FlowControlConfig,
    error::{HtxError, Result, StreamError},
    frame::{Frame, FrameType},
    protocol::StreamState,
};
use bytes::{Bytes, BytesMut};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::{
    sync::{mpsc, oneshot, Notify},
    time::{Duration, Instant},
};
use tracing::{debug, warn};

/// Stream flow control window
#[derive(Debug, Clone)]
pub struct FlowControlWindow {
    /// Current window size
    size: u32,
    /// Initial window size
    initial_size: u32,
    /// Maximum window size
    max_size: u32,
    /// Update threshold (as fraction of window size)
    update_threshold: f64,
    /// Bytes consumed since last update
    consumed_since_update: u32,
}

impl FlowControlWindow {
    pub fn new(config: &FlowControlConfig) -> Self {
        Self {
            size: config.initial_window_size,
            initial_size: config.initial_window_size,
            max_size: config.max_window_size,
            update_threshold: config.update_threshold,
            consumed_since_update: 0,
        }
    }

    /// Check if data can be sent (has window space)
    pub fn can_send(&self, bytes: u32) -> bool {
        self.size >= bytes
    }

    /// Consume window space for sending data
    pub fn consume(&mut self, bytes: u32) -> Result<()> {
        if self.size < bytes {
            return Err(HtxError::FlowControl("Window exceeded".to_string()));
        }
        self.size -= bytes;
        Ok(())
    }

    /// Add window space from incoming WINDOW_UPDATE
    pub fn update(&mut self, increment: u32) -> Result<()> {
        let new_size = self.size.saturating_add(increment);
        if new_size > self.max_size {
            return Err(HtxError::FlowControl("Window size too large".to_string()));
        }
        self.size = new_size;
        Ok(())
    }

    /// Process received data and check if window update is needed
    pub fn process_received(&mut self, bytes: u32) -> Option<u32> {
        self.consumed_since_update += bytes;

        let threshold_bytes = (self.initial_size as f64 * self.update_threshold) as u32;
        if self.consumed_since_update >= threshold_bytes {
            let increment = self.consumed_since_update;
            self.consumed_since_update = 0;
            Some(increment)
        } else {
            None
        }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn available(&self) -> u32 {
        self.size
    }
}

/// HTX stream for multiplexed data transfer
pub struct HtxStream {
    /// Stream ID
    pub id: u64,
    /// Stream state
    state: StreamState,
    /// Send flow control window
    send_window: FlowControlWindow,
    /// Receive flow control window
    receive_window: FlowControlWindow,
    /// Outgoing frame queue
    #[allow(dead_code)]
    outgoing_frames: VecDeque<Frame>,
    /// Incoming data buffer
    incoming_data: BytesMut,
    /// Pending read operations
    pending_reads: VecDeque<oneshot::Sender<Result<Bytes>>>,
    /// Frame sender to connection
    frame_tx: mpsc::UnboundedSender<Frame>,
    /// Stream close notification
    close_notify: Arc<Notify>,
    /// Last activity timestamp
    last_activity: Instant,
    /// Stream creation time
    created_at: Instant,
}

impl HtxStream {
    pub fn new(
        id: u64,
        config: &FlowControlConfig,
        frame_tx: mpsc::UnboundedSender<Frame>,
    ) -> Self {
        Self {
            id,
            state: StreamState::Open,
            send_window: FlowControlWindow::new(config),
            receive_window: FlowControlWindow::new(config),
            outgoing_frames: VecDeque::new(),
            incoming_data: BytesMut::new(),
            pending_reads: VecDeque::new(),
            frame_tx,
            close_notify: Arc::new(Notify::new()),
            last_activity: Instant::now(),
            created_at: Instant::now(),
        }
    }

    /// Send data on this stream
    pub async fn send(&mut self, data: Bytes) -> Result<()> {
        if !matches!(self.state, StreamState::Open) {
            return Err(StreamError::InvalidState.into());
        }

        let data_len = data.len() as u32;

        // Check flow control
        if !self.send_window.can_send(data_len) {
            return Err(HtxError::FlowControl("Send window exceeded".to_string()));
        }

        // Consume flow control window
        self.send_window.consume(data_len)?;

        // Create and send stream frame
        let frame = Frame::stream(self.id, data);
        self.frame_tx
            .send(frame)
            .map_err(|_| HtxError::ConnectionClosed("Connection closed".to_string()))?;

        self.last_activity = Instant::now();
        debug!("Sent {} bytes on stream {}", data_len, self.id);

        Ok(())
    }

    /// Receive data from this stream
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        if matches!(self.state, StreamState::Closed | StreamState::Reset) {
            return Ok(None);
        }

        // If we have buffered data, return it immediately
        if !self.incoming_data.is_empty() {
            let data = self.incoming_data.split().freeze();
            self.last_activity = Instant::now();
            return Ok(Some(data));
        }

        // If stream is half-closed remote, no more data will come
        if matches!(self.state, StreamState::HalfClosedRemote) {
            return Ok(None);
        }

        // Wait for data or stream close
        let (tx, rx) = oneshot::channel();
        self.pending_reads.push_back(tx);

        match rx.await {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None), // Channel was dropped
        }
    }

    /// Process incoming stream frame
    pub fn process_frame(&mut self, frame: Frame) -> Result<()> {
        match frame.frame_type {
            FrameType::Stream => {
                if frame.stream_id != Some(self.id) {
                    return Err(HtxError::Protocol("Stream ID mismatch".to_string()));
                }

                let data = frame.payload;
                let data_len = data.len() as u32;

                // Add to incoming buffer
                self.incoming_data.extend_from_slice(&data);

                // Process flow control
                if let Some(increment) = self.receive_window.process_received(data_len) {
                    let window_update = Frame::window_update(self.id, increment);
                    let _ = self.frame_tx.send(window_update); // Best effort
                }

                // Fulfill pending reads
                if let Some(tx) = self.pending_reads.pop_front() {
                    let data = self.incoming_data.split().freeze();
                    let _ = tx.send(Ok(data));
                }

                self.last_activity = Instant::now();
                debug!("Received {} bytes on stream {}", data_len, self.id);
            }
            FrameType::WindowUpdate => {
                if let Some(increment_bytes) = frame.payload.get(..4) {
                    let increment = u32::from_be_bytes([
                        increment_bytes[0],
                        increment_bytes[1],
                        increment_bytes[2],
                        increment_bytes[3],
                    ]);
                    self.send_window.update(increment)?;
                    debug!("Window updated by {} on stream {}", increment, self.id);
                }
            }
            _ => {
                return Err(HtxError::Protocol(
                    "Invalid frame type for stream".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Close the stream for sending
    pub fn close(&mut self) -> Result<()> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedLocal;
            }
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
                self.close_notify.notify_waiters();
            }
            _ => {} // Already closed or closing
        }

        self.last_activity = Instant::now();
        Ok(())
    }

    /// Reset the stream with error
    pub fn reset(&mut self, error_code: u32) -> Result<()> {
        self.state = StreamState::Reset;
        self.close_notify.notify_waiters();

        // Fail all pending reads
        while let Some(tx) = self.pending_reads.pop_front() {
            let _ = tx.send(Err(StreamError::Reset(error_code).into()));
        }

        warn!("Stream {} reset with code {}", self.id, error_code);
        Ok(())
    }

    /// Wait for stream to close
    pub async fn wait_closed(&self) {
        if matches!(self.state, StreamState::Closed | StreamState::Reset) {
            return;
        }
        self.close_notify.notified().await;
    }

    /// Get stream state
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Get stream statistics
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            id: self.id,
            state: self.state,
            send_window_size: self.send_window.size(),
            receive_window_size: self.receive_window.size(),
            buffered_bytes: self.incoming_data.len(),
            last_activity: self.last_activity,
            age: self.created_at.elapsed(),
        }
    }

    /// Check if stream has been idle too long
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_activity.elapsed() > idle_timeout
    }

    /// Check if stream is writable (has send window space)
    pub fn is_writable(&self) -> bool {
        matches!(self.state, StreamState::Open) && self.send_window.size() > 0
    }

    /// Check if stream is readable (has buffered data or can receive more)
    pub fn is_readable(&self) -> bool {
        !self.incoming_data.is_empty()
            || matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }
}

/// Stream statistics
#[derive(Debug, Clone)]
pub struct StreamStats {
    pub id: u64,
    pub state: StreamState,
    pub send_window_size: u32,
    pub receive_window_size: u32,
    pub buffered_bytes: usize,
    pub last_activity: Instant,
    pub age: Duration,
}

/// Stream manager for handling multiple streams
pub struct StreamManager {
    streams: HashMap<u64, HtxStream>,
    next_client_stream_id: u64,
    next_server_stream_id: u64,
    max_streams: u32,
    flow_config: FlowControlConfig,
    frame_tx: mpsc::UnboundedSender<Frame>,
}

impl StreamManager {
    pub fn new(
        _is_client: bool,
        max_streams: u32,
        flow_config: FlowControlConfig,
        frame_tx: mpsc::UnboundedSender<Frame>,
    ) -> Self {
        Self {
            streams: HashMap::new(),
            next_client_stream_id: 1, // Client streams are odd
            next_server_stream_id: 2, // Server streams are even
            max_streams,
            flow_config,
            frame_tx,
        }
    }

    /// Open a new outgoing stream
    pub fn open_stream(&mut self, is_client: bool) -> Result<u64> {
        if self.streams.len() >= self.max_streams as usize {
            return Err(HtxError::Stream("Too many streams".to_string()));
        }

        let stream_id = if is_client {
            let id = self.next_client_stream_id;
            self.next_client_stream_id += 2;
            id
        } else {
            let id = self.next_server_stream_id;
            self.next_server_stream_id += 2;
            id
        };

        let stream = HtxStream::new(stream_id, &self.flow_config, self.frame_tx.clone());
        self.streams.insert(stream_id, stream);

        debug!("Opened stream {}", stream_id);
        Ok(stream_id)
    }

    /// Get a mutable reference to a stream
    pub fn get_stream_mut(&mut self, stream_id: u64) -> Option<&mut HtxStream> {
        self.streams.get_mut(&stream_id)
    }

    /// Get a reference to a stream
    pub fn get_stream(&self, stream_id: u64) -> Option<&HtxStream> {
        self.streams.get(&stream_id)
    }

    /// Process incoming frame for the appropriate stream
    pub fn process_frame(&mut self, frame: Frame) -> Result<()> {
        match frame.frame_type {
            FrameType::Stream | FrameType::WindowUpdate => {
                let stream_id = frame
                    .stream_id
                    .ok_or_else(|| HtxError::Protocol("Missing stream ID".to_string()))?;

                // Create stream if it doesn't exist (for incoming streams)
                if !self.streams.contains_key(&stream_id) {
                    if self.streams.len() >= self.max_streams as usize {
                        return Err(HtxError::Stream("Too many streams".to_string()));
                    }

                    let stream =
                        HtxStream::new(stream_id, &self.flow_config, self.frame_tx.clone());
                    self.streams.insert(stream_id, stream);
                    debug!("Created incoming stream {}", stream_id);
                }

                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.process_frame(frame)?;
                }
            }
            _ => {
                return Err(HtxError::Protocol(
                    "Non-stream frame in stream manager".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Close a stream
    pub fn close_stream(&mut self, stream_id: u64) -> Result<()> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.close()?;
        }
        Ok(())
    }

    /// Remove closed streams
    pub fn cleanup_closed_streams(&mut self) {
        self.streams.retain(|&stream_id, stream| {
            if matches!(stream.state(), StreamState::Closed | StreamState::Reset) {
                debug!("Cleaned up closed stream {}", stream_id);
                false
            } else {
                true
            }
        });
    }

    /// Get all stream IDs
    pub fn stream_ids(&self) -> Vec<u64> {
        self.streams.keys().copied().collect()
    }

    /// Get stream count
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Get streams that are idle
    pub fn idle_streams(&self, idle_timeout: Duration) -> Vec<u64> {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.is_idle(idle_timeout))
            .map(|(&id, _)| id)
            .collect()
    }

    /// Get aggregate statistics for all streams
    pub fn aggregate_stats(&self) -> AggregateStreamStats {
        let mut total_send_window = 0u64;
        let mut total_receive_window = 0u64;
        let mut total_buffered = 0usize;
        let mut state_counts = HashMap::new();

        for stream in self.streams.values() {
            let stats = stream.stats();
            total_send_window += stats.send_window_size as u64;
            total_receive_window += stats.receive_window_size as u64;
            total_buffered += stats.buffered_bytes;

            *state_counts.entry(stats.state).or_insert(0) += 1;
        }

        AggregateStreamStats {
            total_streams: self.streams.len(),
            total_send_window,
            total_receive_window,
            total_buffered_bytes: total_buffered,
            state_counts,
        }
    }
}

/// Aggregate statistics for all streams
#[derive(Debug, Clone)]
pub struct AggregateStreamStats {
    pub total_streams: usize,
    pub total_send_window: u64,
    pub total_receive_window: u64,
    pub total_buffered_bytes: usize,
    pub state_counts: HashMap<StreamState, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_flow_control_window() {
        let config = FlowControlConfig {
            initial_window_size: 1000,
            max_window_size: 2000,
            update_threshold: 0.5,
        };

        let mut window = FlowControlWindow::new(&config);

        // Test consumption
        assert!(window.can_send(500));
        window.consume(500).unwrap();
        assert_eq!(window.size(), 500);

        // Test update
        window.update(300).unwrap();
        assert_eq!(window.size(), 800);

        // Test receive processing
        let update = window.process_received(600);
        assert_eq!(update, Some(600)); // Should trigger update at 50% threshold
    }

    #[test]
    fn test_stream_manager() {
        let config = FlowControlConfig::default();
        let (frame_tx, _) = mpsc::unbounded_channel();

        let mut manager = StreamManager::new(true, 100, config, frame_tx);

        // Test stream creation
        let stream_id = manager.open_stream(true).unwrap();
        assert_eq!(stream_id, 1); // First client stream

        let stream_id2 = manager.open_stream(true).unwrap();
        assert_eq!(stream_id2, 3); // Second client stream

        // Test server streams
        let stream_id3 = manager.open_stream(false).unwrap();
        assert_eq!(stream_id3, 2); // First server stream

        assert_eq!(manager.stream_count(), 3);
    }

    #[tokio::test]
    async fn test_stream_send_receive() {
        let config = FlowControlConfig::default();
        let (frame_tx, mut frame_rx) = mpsc::unbounded_channel();

        let mut stream = HtxStream::new(1, &config, frame_tx);

        // Test send
        let data = Bytes::from("hello world");
        stream.send(data.clone()).await.unwrap();

        // Should have sent a frame
        let frame = frame_rx.recv().await.unwrap();
        assert_eq!(frame.frame_type, FrameType::Stream);
        assert_eq!(frame.stream_id, Some(1));
        assert_eq!(frame.payload, data);
    }
}
