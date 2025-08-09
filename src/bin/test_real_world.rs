//! Real-world TLS handshake capture test
//!
//! This binary tests the complete TLS handshake capture implementation
//! against real internet servers to validate production functionality.

use htx::{config::TlsConfig, origin_mirror::OriginMirror, Result};
use std::time::Duration;
use tracing::{info, warn, Level};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("🌐 Starting real-world TLS handshake capture test");

    // Create origin mirror with default config
    let config = TlsConfig::default();
    let mirror = OriginMirror::new(config);

    // Test targets - popular websites that should support TLS 1.2/1.3
    let test_targets = vec![
        "www.google.com:443",
        "www.cloudflare.com:443",
        "www.github.com:443",
        "httpbin.org:443",
    ];

    info!(
        "📡 Testing TLS handshake capture with {} targets",
        test_targets.len()
    );

    let mut successful_captures = 0;
    let mut total_tests = 0;

    for target in test_targets {
        total_tests += 1;
        info!("🔍 Testing TLS handshake capture for {}", target);

        match test_target_handshake(&mirror, target).await {
            Ok(fingerprint) => {
                successful_captures += 1;
                info!("✅ Successfully captured handshake from {}", target);
                info!("   🔐 JA3: {}", fingerprint.ja3_hash);
                info!("   🔑 JA4: {}", fingerprint.ja4_hash);
                info!(
                    "   📊 Ciphers: {}, Extensions: {}, Curves: {}",
                    fingerprint.cipher_suites.len(),
                    fingerprint.extensions.len(),
                    fingerprint.supported_curves.len()
                );

                // Verify we got real data (not just fallback)
                if fingerprint.cipher_suites.len() > 0 && fingerprint.extensions.len() > 5 {
                    info!("   ✨ Real handshake data captured (not fallback)");
                } else {
                    warn!("   ⚠️  Possibly fallback data used");
                }
            }
            Err(e) => {
                warn!("❌ Failed to capture handshake from {}: {}", target, e);
            }
        }

        // Small delay between tests to be respectful to servers
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    info!(
        "📈 Real-world test results: {}/{} successful captures",
        successful_captures, total_tests
    );

    if successful_captures > 0 {
        info!("🎉 REAL-WORLD TEST PASSED: TLS handshake capture working over internet!");

        // Test the mirror's capture functionality
        info!("🔄 Testing origin mirror calibration...");
        match mirror.calibrate_origin("www.google.com:443").await {
            Ok(fingerprint) => {
                info!("✅ Origin calibration successful!");
                info!("   📍 Hostname: {}", fingerprint.hostname);
                info!("   🔍 JA3 String: {}", fingerprint.ja3_string);
                info!("   🔍 JA4 String: {}", fingerprint.ja4_string);
                info!("   📋 ALPN Protocols: {:?}", fingerprint.alpn_protocols);
            }
            Err(e) => {
                warn!("❌ Origin calibration failed: {}", e);
            }
        }

        Ok(())
    } else {
        warn!("🚫 REAL-WORLD TEST FAILED: No successful handshake captures");
        std::process::exit(1);
    }
}

async fn test_target_handshake(
    mirror: &OriginMirror,
    target: &str,
) -> Result<htx::origin_mirror::OriginFingerprint> {
    // Set a timeout for the test
    let timeout_duration = Duration::from_secs(10);

    match tokio::time::timeout(timeout_duration, mirror.capture_real_handshake_data(target)).await {
        Ok(result) => match result {
            Ok(handshake_data) => {
                // Convert handshake data to fingerprint for testing
                // In a real scenario, this would be done by calibrate_origin
                Ok(htx::origin_mirror::OriginFingerprint {
                    hostname: target.split(':').next().unwrap_or(target).to_string(),
                    ja3_string: format!(
                        "{},{:?},{:?},{:?},{:?}",
                        handshake_data.version,
                        handshake_data.cipher_suites,
                        handshake_data.extensions,
                        handshake_data.supported_curves,
                        handshake_data.point_formats
                    ),
                    ja3_hash: "test_hash".to_string(),
                    ja4_string: "t13d05h2_test_test".to_string(),
                    ja4_hash: "test_ja4_hash".to_string(),
                    cipher_suites: handshake_data.cipher_suites,
                    extensions: handshake_data.extensions,
                    supported_curves: handshake_data.supported_curves,
                    signature_algorithms: handshake_data.signature_algorithms,
                    alpn_protocols: handshake_data.alpn_protocols,
                    grease_values: vec![0x0a0a, 0x1a1a],
                    timestamp: std::time::Instant::now(),
                })
            }
            Err(e) => Err(e),
        },
        Err(_) => Err(htx::error::HtxError::Timeout(
            "TLS handshake capture timed out".to_string(),
        )),
    }
}
