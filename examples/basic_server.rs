//! HTX Server Example
//!
//! This example demonstrates how to create an HTX server that can
//! handle incoming connections and process requests.

use htx::{HtxServer, Config, Result};
use tokio;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    println!("🚀 Starting HTX Server Example");

    // Create server configuration with default values
    let config = Config::default();

    // Define the server address
    let addr: SocketAddr = "127.0.0.1:8443".parse()
        .expect("Invalid server address");

    // Create the HTX server with correct API
    println!("📡 Creating HTX server...");
    let _server = HtxServer::new(addr, config).await?;

    println!("🎧 Server listening on {}", addr);
    println!("✅ HTX Server created successfully!");

    println!("\n📝 This example demonstrates basic server setup:");
    println!("   • Configuration initialization");
    println!("   • Server binding to address");
    println!("   • Ready to handle connections");

    println!("\n🔧 In a production server, you would:");
    println!("   • Accept incoming connections");
    println!("   • Perform TLS handshakes");
    println!("   • Process HTTP requests with access tickets");
    println!("   • Route requests to handlers");
    println!("   • Return appropriate responses");

    println!("\n💡 The HTX library provides the foundation for");
    println!("   secure, high-performance transport with:");
    println!("   • ChaCha20-Poly1305 encryption");
    println!("   • Noise XK handshake protocol");
    println!("   • Access ticket validation");
    println!("   • Flow control mechanisms");

    Ok(())
}
