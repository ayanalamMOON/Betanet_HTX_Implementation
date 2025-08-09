use crate::{
    error::{HtxError, Result},
    frame::{Frame, FrameType},
};
use bytes::Bytes;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Flow control manager for HTX connections
pub struct FlowControlManager {
    connection_window: Arc<Mutex<FlowControlWindow>>,
    stream_windows: Arc<Mutex<HashMap<u32, FlowControlWindow>>>,
    window_updates: mpsc::UnboundedSender<WindowUpdate>,
    initial_window_size: u32,
    max_window_size: u32,
    auto_tune_enabled: bool,
}

impl FlowControlManager {
    /// Create a new flow control manager
    pub fn new(initial_window_size: u32) -> (Self, mpsc::UnboundedReceiver<WindowUpdate>) {
        let (tx, rx) = mpsc::unbounded_channel();

        let manager = Self {
            connection_window: Arc::new(Mutex::new(FlowControlWindow::new(
                0, // Connection stream ID
                initial_window_size,
            ))),
            stream_windows: Arc::new(Mutex::new(HashMap::new())),
            window_updates: tx,
            initial_window_size,
            max_window_size: initial_window_size * 4, // Allow 4x growth
            auto_tune_enabled: true,
        };

        (manager, rx)
    }

    /// Allocate send capacity for a stream
    pub async fn allocate_send_capacity(&self, stream_id: u32, bytes: u32) -> Result<()> {
        // Check connection-level window
        let connection_available = {
            let mut conn_window = self.connection_window.lock().unwrap();
            if conn_window.available() >= bytes {
                conn_window.consume(bytes)?;
                true
            } else {
                false
            }
        };

        if !connection_available {
            return Err(HtxError::FlowControl(
                "Connection window exhausted".to_string(),
            ));
        }

        // Check stream-level window
        let stream_available = {
            let mut stream_windows = self.stream_windows.lock().unwrap();
            let stream_window = stream_windows
                .entry(stream_id)
                .or_insert_with(|| FlowControlWindow::new(stream_id, self.initial_window_size));

            if stream_window.available() >= bytes {
                stream_window.consume(bytes)?;
                true
            } else {
                false
            }
        };

        if !stream_available {
            // Refund connection window
            {
                let mut conn_window = self.connection_window.lock().unwrap();
                conn_window.return_capacity(bytes);
            }
            return Err(HtxError::FlowControl(format!(
                "Stream {} window exhausted",
                stream_id
            )));
        }

        debug!("Allocated {} bytes for stream {}", bytes, stream_id);
        Ok(())
    }

    /// Process received data and update windows
    pub fn process_received_data(&self, stream_id: u32, bytes: u32) -> Result<()> {
        // Update connection window
        let conn_update = {
            let mut conn_window = self.connection_window.lock().unwrap();
            conn_window.receive_data(bytes)?;

            // Check if we should send a window update
            if self.should_send_window_update(&conn_window) {
                let increment = self.calculate_window_update(&conn_window);
                conn_window.send_update(increment)?;
                Some(WindowUpdate {
                    stream_id: 0,
                    increment,
                })
            } else {
                None
            }
        };

        // Update stream window
        let stream_update = if stream_id != 0 {
            let mut stream_windows = self.stream_windows.lock().unwrap();
            let stream_window = stream_windows
                .entry(stream_id)
                .or_insert_with(|| FlowControlWindow::new(stream_id, self.initial_window_size));

            stream_window.receive_data(bytes)?;

            if self.should_send_window_update(stream_window) {
                let increment = self.calculate_window_update(stream_window);
                stream_window.send_update(increment)?;
                Some(WindowUpdate {
                    stream_id,
                    increment,
                })
            } else {
                None
            }
        } else {
            None
        };

        // Send window updates
        if let Some(update) = conn_update {
            let _ = self.window_updates.send(update);
        }

        if let Some(update) = stream_update {
            let _ = self.window_updates.send(update);
        }

        debug!("Processed {} bytes for stream {}", bytes, stream_id);
        Ok(())
    }

    /// Handle received window update frame
    pub fn handle_window_update(&self, stream_id: u32, increment: u32) -> Result<()> {
        if stream_id == 0 {
            // Connection-level update
            let mut conn_window = self.connection_window.lock().unwrap();
            conn_window.receive_update(increment)?;
            debug!("Connection window updated by {}", increment);
        } else {
            // Stream-level update
            let mut stream_windows = self.stream_windows.lock().unwrap();
            if let Some(stream_window) = stream_windows.get_mut(&stream_id) {
                stream_window.receive_update(increment)?;
                debug!("Stream {} window updated by {}", stream_id, increment);
            } else {
                warn!("Window update for unknown stream {}", stream_id);
            }
        }

        Ok(())
    }

    /// Create a new stream with initial flow control window
    pub fn create_stream(&self, stream_id: u32) -> Result<()> {
        let mut stream_windows = self.stream_windows.lock().unwrap();

        if stream_windows.contains_key(&stream_id) {
            return Err(HtxError::Protocol(format!(
                "Stream {} already exists",
                stream_id
            )));
        }

        let window = FlowControlWindow::new(stream_id, self.initial_window_size);
        stream_windows.insert(stream_id, window);

        debug!("Created flow control window for stream {}", stream_id);
        Ok(())
    }

    /// Remove stream flow control window
    pub fn remove_stream(&self, stream_id: u32) {
        let mut stream_windows = self.stream_windows.lock().unwrap();
        if stream_windows.remove(&stream_id).is_some() {
            debug!("Removed flow control window for stream {}", stream_id);
        }
    }

    /// Check if we should send a window update
    fn should_send_window_update(&self, window: &FlowControlWindow) -> bool {
        // Send update when we've received more than 50% of the window size since last update
        let threshold = self.initial_window_size / 2;
        window.bytes_received_since_update >= threshold
    }

    /// Calculate window update increment
    fn calculate_window_update(&self, window: &FlowControlWindow) -> u32 {
        if self.auto_tune_enabled {
            // Auto-tune based on recent usage patterns
            let recent_usage = window.bytes_received_since_update;
            let suggested_size = recent_usage * 2; // Double recent usage

            // Cap at max window size
            suggested_size.min(self.max_window_size - window.window_size)
        } else {
            // Fixed increment
            window.bytes_received_since_update
        }
    }

    /// Get connection window status
    pub fn connection_window_status(&self) -> WindowStatus {
        let window = self.connection_window.lock().unwrap();
        WindowStatus {
            stream_id: 0,
            window_size: window.window_size,
            available: window.available(),
            bytes_sent: window.bytes_sent,
            bytes_received: window.bytes_received,
        }
    }

    /// Get stream window status
    pub fn stream_window_status(&self, stream_id: u32) -> Option<WindowStatus> {
        let stream_windows = self.stream_windows.lock().unwrap();
        stream_windows.get(&stream_id).map(|window| WindowStatus {
            stream_id,
            window_size: window.window_size,
            available: window.available(),
            bytes_sent: window.bytes_sent,
            bytes_received: window.bytes_received,
        })
    }

    /// List all active stream IDs
    pub fn active_streams(&self) -> Vec<u32> {
        let stream_windows = self.stream_windows.lock().unwrap();
        stream_windows.keys().cloned().collect()
    }

    /// Enable or disable auto-tuning
    pub fn set_auto_tune(&mut self, enabled: bool) {
        self.auto_tune_enabled = enabled;
    }
}

/// Individual flow control window
#[derive(Debug)]
pub struct FlowControlWindow {
    #[allow(dead_code)]
    stream_id: u32,
    window_size: u32,
    bytes_sent: u32,
    bytes_received: u32,
    bytes_received_since_update: u32,
    last_update_time: Instant,
}

impl FlowControlWindow {
    /// Create a new flow control window
    pub fn new(stream_id: u32, initial_size: u32) -> Self {
        Self {
            stream_id,
            window_size: initial_size,
            bytes_sent: 0,
            bytes_received: 0,
            bytes_received_since_update: 0,
            last_update_time: Instant::now(),
        }
    }

    /// Get available send capacity
    pub fn available(&self) -> u32 {
        self.window_size.saturating_sub(self.bytes_sent)
    }

    /// Consume send capacity
    pub fn consume(&mut self, bytes: u32) -> Result<()> {
        if self.available() < bytes {
            return Err(HtxError::FlowControl(format!(
                "Insufficient window capacity: available={}, requested={}",
                self.available(),
                bytes
            )));
        }

        self.bytes_sent += bytes;
        Ok(())
    }

    /// Return unused capacity
    pub fn return_capacity(&mut self, bytes: u32) {
        self.bytes_sent = self.bytes_sent.saturating_sub(bytes);
    }

    /// Record received data
    pub fn receive_data(&mut self, bytes: u32) -> Result<()> {
        self.bytes_received += bytes;
        self.bytes_received_since_update += bytes;
        Ok(())
    }

    /// Handle window update from peer
    pub fn receive_update(&mut self, increment: u32) -> Result<()> {
        if increment == 0 {
            return Err(HtxError::Protocol("Zero window update".to_string()));
        }

        // Check for overflow
        if self.window_size > u32::MAX - increment {
            return Err(HtxError::Protocol("Window update overflow".to_string()));
        }

        self.window_size += increment;
        Ok(())
    }

    /// Send window update to peer
    pub fn send_update(&mut self, increment: u32) -> Result<()> {
        self.window_size += increment;
        self.bytes_received_since_update = 0;
        self.last_update_time = Instant::now();
        Ok(())
    }

    /// Check if window is blocked
    pub fn is_blocked(&self) -> bool {
        self.available() == 0
    }

    /// Get window utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.window_size == 0 {
            0.0
        } else {
            (self.bytes_sent as f64 / self.window_size as f64) * 100.0
        }
    }
}

/// Window update notification
#[derive(Debug, Clone)]
pub struct WindowUpdate {
    pub stream_id: u32,
    pub increment: u32,
}

impl WindowUpdate {
    /// Convert to HTX frame
    pub fn to_frame(&self) -> Frame {
        Frame {
            frame_type: FrameType::WindowUpdate,
            stream_id: Some(self.stream_id as u64),
            payload: Bytes::from(self.increment.to_be_bytes().to_vec()),
        }
    }
}

/// Window status information
#[derive(Debug, Clone)]
pub struct WindowStatus {
    pub stream_id: u32,
    pub window_size: u32,
    pub available: u32,
    pub bytes_sent: u32,
    pub bytes_received: u32,
}

/// Flow control configuration
#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    pub initial_window_size: u32,
    pub max_window_size: u32,
    pub auto_tune_enabled: bool,
    pub update_threshold: f64, // Percentage of window to trigger update
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            initial_window_size: 65535,        // 64 KB
            max_window_size: 16 * 1024 * 1024, // 16 MB
            auto_tune_enabled: true,
            update_threshold: 0.5, // 50%
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_control_window() {
        let mut window = FlowControlWindow::new(1, 1000);

        assert_eq!(window.available(), 1000);
        assert!(!window.is_blocked());

        // Consume capacity
        window.consume(500).unwrap();
        assert_eq!(window.available(), 500);

        // Consume remaining capacity
        window.consume(500).unwrap();
        assert_eq!(window.available(), 0);
        assert!(window.is_blocked());

        // Should fail to consume more
        assert!(window.consume(1).is_err());
    }

    #[test]
    fn test_window_update() {
        let mut window = FlowControlWindow::new(1, 1000);

        // Consume all capacity
        window.consume(1000).unwrap();
        assert_eq!(window.available(), 0);

        // Receive window update
        window.receive_update(500).unwrap();
        assert_eq!(window.available(), 500);
        assert_eq!(window.window_size, 1500);
    }

    #[test]
    fn test_window_overflow() {
        let mut window = FlowControlWindow::new(1, u32::MAX);

        // Should fail with overflow
        assert!(window.receive_update(1).is_err());
    }

    #[tokio::test]
    async fn test_flow_control_manager() {
        let (manager, mut updates) = FlowControlManager::new(1000);

        // Create a stream
        manager.create_stream(1).unwrap();

        // Process received data that exceeds window update threshold
        // With initial window 1000, threshold is 500
        // We need to receive >= 500 bytes to trigger update
        manager.process_received_data(1, 600).unwrap();

        // Should receive at least one window update (could be connection and/or stream)
        let mut updates_received = Vec::new();
        while let Ok(update) = updates.try_recv() {
            updates_received.push(update);
        }

        assert!(
            !updates_received.is_empty(),
            "Expected at least one window update"
        );

        // Should have a stream update for stream 1
        let stream_update = updates_received.iter().find(|u| u.stream_id == 1);
        assert!(
            stream_update.is_some(),
            "Expected stream update for stream 1"
        );

        let stream_update = stream_update.unwrap();
        assert!(stream_update.increment > 0);
    }

    #[test]
    fn test_window_update_frame() {
        let update = WindowUpdate {
            stream_id: 1,
            increment: 1000,
        };

        let frame = update.to_frame();
        assert_eq!(frame.frame_type, FrameType::WindowUpdate);
        assert_eq!(frame.stream_id, Some(1));
        assert_eq!(frame.payload.as_ref(), &1000u32.to_be_bytes());
    }
}
