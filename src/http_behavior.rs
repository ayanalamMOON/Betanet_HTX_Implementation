use crate::{error::Result, frame::Frame};
use bytes::Bytes;
use std::time::{Duration, Instant};
use tokio::{
    sync::mpsc,
    time::{interval, sleep_until, Instant as TokioInstant},
};
use tracing::{debug, info};

/// HTTP/2 and HTTP/3 behavior emulation for covert traffic
pub struct HttpBehaviorEmulator {
    /// Frame sender for the connection
    frame_tx: mpsc::UnboundedSender<Frame>,
    /// HTTP version being emulated
    http_version: HttpVersion,
    /// Last activity timestamp
    last_activity: Instant,
    /// Ping interval configuration
    ping_config: PingConfig,
    /// Priority configuration
    priority_config: PriorityConfig,
    /// Connection padding configuration
    padding_config: PaddingConfig,
}

/// HTTP version being emulated
#[derive(Debug, Clone, Copy)]
pub enum HttpVersion {
    Http2,
    Http3,
}

/// Ping frame configuration for HTTP/2-3 behavior
#[derive(Debug, Clone)]
pub struct PingConfig {
    /// Base interval between pings
    pub base_interval: Duration,
    /// Random jitter range (±jitter)
    pub jitter: Duration,
    /// Enable adaptive ping intervals
    pub adaptive: bool,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            base_interval: Duration::from_secs(30),
            jitter: Duration::from_secs(5),
            adaptive: true,
        }
    }
}

/// Priority frame configuration
#[derive(Debug, Clone)]
pub struct PriorityConfig {
    /// Enable priority frame injection
    pub enabled: bool,
    /// Frequency of priority updates
    pub update_frequency: Duration,
    /// Stream priorities to cycle through
    pub priority_levels: Vec<u8>,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_frequency: Duration::from_secs(60),
            priority_levels: vec![0, 16, 32, 48, 64],
        }
    }
}

/// Connection padding configuration
#[derive(Debug, Clone)]
pub struct PaddingConfig {
    /// Enable idle padding
    pub enabled: bool,
    /// Minimum padding size
    pub min_size: usize,
    /// Maximum padding size
    pub max_size: usize,
    /// Padding interval during idle periods
    pub idle_interval: Duration,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_size: 64,
            max_size: 512,
            idle_interval: Duration::from_secs(45),
        }
    }
}

impl HttpBehaviorEmulator {
    /// Create a new HTTP behavior emulator
    pub fn new(frame_tx: mpsc::UnboundedSender<Frame>, http_version: HttpVersion) -> Self {
        Self {
            frame_tx,
            http_version,
            last_activity: Instant::now(),
            ping_config: PingConfig::default(),
            priority_config: PriorityConfig::default(),
            padding_config: PaddingConfig::default(),
        }
    }

    /// Configure ping behavior
    pub fn with_ping_config(mut self, config: PingConfig) -> Self {
        self.ping_config = config;
        self
    }

    /// Configure priority behavior
    pub fn with_priority_config(mut self, config: PriorityConfig) -> Self {
        self.priority_config = config;
        self
    }

    /// Configure padding behavior
    pub fn with_padding_config(mut self, config: PaddingConfig) -> Self {
        self.padding_config = config;
        self
    }

    /// Start HTTP behavior emulation tasks
    pub async fn start_emulation(&self) -> Result<()> {
        let frame_tx = self.frame_tx.clone();
        let http_version = self.http_version;
        let ping_config = self.ping_config.clone();
        let priority_config = self.priority_config.clone();
        let padding_config = self.padding_config.clone();

        // Start ping task
        let ping_tx = frame_tx.clone();
        tokio::spawn(async move {
            Self::ping_task(ping_tx, http_version, ping_config).await;
        });

        // Start priority task if enabled
        if priority_config.enabled {
            let priority_tx = frame_tx.clone();
            tokio::spawn(async move {
                Self::priority_task(priority_tx, http_version, priority_config).await;
            });
        }

        // Start padding task if enabled
        if padding_config.enabled {
            let padding_tx = frame_tx.clone();
            tokio::spawn(async move {
                Self::padding_task(padding_tx, http_version, padding_config).await;
            });
        }

        info!("HTTP behavior emulation started for {:?}", http_version);
        Ok(())
    }

    /// Ping task - sends keep-alive pings at adaptive intervals
    async fn ping_task(
        frame_tx: mpsc::UnboundedSender<Frame>,
        http_version: HttpVersion,
        config: PingConfig,
    ) {
        let mut last_ping = Instant::now();

        loop {
            let next_interval = if config.adaptive {
                // Adaptive interval based on HTTP version and traffic patterns
                let base = match http_version {
                    HttpVersion::Http2 => config.base_interval,
                    HttpVersion::Http3 => config.base_interval + Duration::from_secs(10),
                };

                let jitter_ms = {
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    rng.gen_range(0..config.jitter.as_millis() as u64 * 2)
                };
                let jitter = Duration::from_millis(jitter_ms) - config.jitter;

                base + jitter
            } else {
                config.base_interval
            };

            sleep_until(TokioInstant::from_std(last_ping + next_interval)).await;

            // Send ping frame
            let ping_data = match http_version {
                HttpVersion::Http2 => {
                    // HTTP/2 ping with 8-byte payload
                    let mut data = vec![0u8; 8];
                    use rand::RngCore;
                    rand::thread_rng().fill_bytes(&mut data[..]);
                    Bytes::from(data)
                }
                HttpVersion::Http3 => {
                    // HTTP/3 ping with variable payload
                    let size = {
                        use rand::Rng;
                        rand::thread_rng().gen_range(8..64)
                    };
                    let mut data = vec![0u8; size];
                    use rand::RngCore;
                    rand::thread_rng().fill_bytes(&mut data[..]);
                    Bytes::from(data)
                }
            };

            let ping_frame = Frame::ping(ping_data);
            if let Err(e) = frame_tx.send(ping_frame) {
                debug!("Failed to send ping frame: {}", e);
                break;
            }

            last_ping = Instant::now();
            debug!("Sent HTTP {:?} ping frame", http_version);
        }
    }

    /// Priority task - sends PRIORITY frames to mimic browser behavior
    async fn priority_task(
        frame_tx: mpsc::UnboundedSender<Frame>,
        http_version: HttpVersion,
        config: PriorityConfig,
    ) {
        let mut interval = interval(config.update_frequency);
        let mut stream_id = 1u64;

        loop {
            interval.tick().await;

            // Only HTTP/2 has explicit PRIORITY frames
            if matches!(http_version, HttpVersion::Http2) {
                let priority_level = {
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    config.priority_levels[rng.gen_range(0..config.priority_levels.len())]
                };

                // Create a synthetic priority frame (using our close frame as placeholder)
                let priority_data =
                    format!("PRIORITY:stream_id={},weight={}", stream_id, priority_level);
                let priority_frame = Frame::close(&priority_data);

                if let Err(e) = frame_tx.send(priority_frame) {
                    debug!("Failed to send priority frame: {}", e);
                    break;
                }

                stream_id += 2; // Client streams are odd-numbered
                debug!(
                    "Sent HTTP/2 priority frame for stream {} with weight {}",
                    stream_id - 2,
                    priority_level
                );
            }
        }
    }

    /// Padding task - sends padding during idle periods
    async fn padding_task(
        frame_tx: mpsc::UnboundedSender<Frame>,
        http_version: HttpVersion,
        config: PaddingConfig,
    ) {
        let mut interval = interval(config.idle_interval);

        loop {
            interval.tick().await;

            let padding_size = {
                use rand::Rng;
                rand::thread_rng().gen_range(config.min_size..=config.max_size)
            };
            let mut padding_data = vec![0u8; padding_size];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut padding_data[..]);

            // Create padding frame using ping frame type
            let padding_frame = Frame::ping(Bytes::from(padding_data));

            if let Err(e) = frame_tx.send(padding_frame) {
                debug!("Failed to send padding frame: {}", e);
                break;
            }

            debug!(
                "Sent HTTP {:?} padding frame ({} bytes)",
                http_version, padding_size
            );
        }
    }

    /// Notify about connection activity to adjust behavior
    pub fn record_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if connection is idle
    pub fn is_idle(&self, threshold: Duration) -> bool {
        self.last_activity.elapsed() > threshold
    }

    /// Generate HTTP/2-style settings frame data
    pub fn generate_settings_frame(&self) -> Bytes {
        let mut settings = Vec::new();

        // SETTINGS_HEADER_TABLE_SIZE (0x1) = 4096
        settings.extend_from_slice(&[0x00, 0x01]);
        settings.extend_from_slice(&4096u32.to_be_bytes());

        // SETTINGS_ENABLE_PUSH (0x2) = 0 (disabled)
        settings.extend_from_slice(&[0x00, 0x02]);
        settings.extend_from_slice(&0u32.to_be_bytes());

        // SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 100
        settings.extend_from_slice(&[0x00, 0x03]);
        settings.extend_from_slice(&100u32.to_be_bytes());

        // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 65535
        settings.extend_from_slice(&[0x00, 0x04]);
        settings.extend_from_slice(&65535u32.to_be_bytes());

        // SETTINGS_MAX_FRAME_SIZE (0x5) = 16384
        settings.extend_from_slice(&[0x00, 0x05]);
        settings.extend_from_slice(&16384u32.to_be_bytes());

        Bytes::from(settings)
    }

    /// Generate HTTP/3-style settings frame data
    pub fn generate_h3_settings_frame(&self) -> Bytes {
        let mut settings = Vec::new();

        // QPACK_MAX_TABLE_CAPACITY
        settings.extend_from_slice(&[0x01]);
        settings.extend_from_slice(&4096u32.to_le_bytes());

        // MAX_FIELD_SECTION_SIZE
        settings.extend_from_slice(&[0x06]);
        settings.extend_from_slice(&8192u32.to_le_bytes());

        // QPACK_BLOCKED_STREAMS
        settings.extend_from_slice(&[0x07]);
        settings.extend_from_slice(&100u32.to_le_bytes());

        Bytes::from(settings)
    }
}

impl HttpVersion {
    /// Get typical frame size for this HTTP version
    pub fn typical_frame_size(&self) -> usize {
        match self {
            HttpVersion::Http2 => 16384, // 16KB default frame size
            HttpVersion::Http3 => 8192,  // 8KB typical QUIC packet size
        }
    }

    /// Get connection keep-alive interval
    pub fn keep_alive_interval(&self) -> Duration {
        match self {
            HttpVersion::Http2 => Duration::from_secs(30),
            HttpVersion::Http3 => Duration::from_secs(45),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_http_behavior_emulator() {
        let (frame_tx, _frame_rx) = mpsc::unbounded_channel();

        let emulator = HttpBehaviorEmulator::new(frame_tx, HttpVersion::Http2);

        assert!(matches!(emulator.http_version, HttpVersion::Http2));
        assert!(emulator.ping_config.adaptive);
        assert!(emulator.priority_config.enabled);
        assert!(emulator.padding_config.enabled);
    }

    #[test]
    fn test_http_version_properties() {
        assert_eq!(HttpVersion::Http2.typical_frame_size(), 16384);
        assert_eq!(HttpVersion::Http3.typical_frame_size(), 8192);

        assert_eq!(
            HttpVersion::Http2.keep_alive_interval(),
            Duration::from_secs(30)
        );
        assert_eq!(
            HttpVersion::Http3.keep_alive_interval(),
            Duration::from_secs(45)
        );
    }

    #[test]
    fn test_settings_frames() {
        let (frame_tx, _) = mpsc::unbounded_channel();
        let emulator = HttpBehaviorEmulator::new(frame_tx, HttpVersion::Http2);

        let h2_settings = emulator.generate_settings_frame();
        assert!(!h2_settings.is_empty());

        let h3_settings = emulator.generate_h3_settings_frame();
        assert!(!h3_settings.is_empty());
    }
}
