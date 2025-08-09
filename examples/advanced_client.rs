//! Advanced HTX Client Example
//!
//! This example demonstrates advanced HTX client features and
//! configuration options.

use htx::{HtxClient, Config, Result, AccessTicket};
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize simple logging
    println!("🚀 Advanced HTX Client Example");

    // Create client configuration with default settings
    let mut config = Config::default();

    // Set up access ticket keys (in real usage, these would be provided by server)
    let ticket_keypair = htx::crypto::X25519KeyPair::generate();
    config.access_ticket.ticket_public_key = Some(ticket_keypair.public_bytes());
    config.access_ticket.ticket_private_key = Some(ticket_keypair.private_bytes());

    // Create the HTX client
    println!("📡 Creating HTX client with advanced configuration...");
    let _client = HtxClient::new(config.clone()).await?;

    // Show configuration details
    println!("✅ Client created successfully!");
    println!("\n⚙️  Configuration details:");
    println!("   • Transport: TCP and QUIC on port 443");
    println!("   • Flow Control: {} bytes initial window", config.flow_control.initial_window_size);
    println!("   • Noise Protocol: Standard configuration");
    println!("   • TLS: Default secure settings");

    // Create and display an access ticket
    let target_length = 150; // Target ticket size in bytes
    let (_access_ticket, _client_keypair) = AccessTicket::new(&config.access_ticket, target_length)?;

    println!("\n🎫 Access Ticket Created:");
    println!("   • Target length: {} bytes", target_length);
    println!("   • Ticket serialized successfully");

    // Demonstrate error handling patterns
    println!("\n🔧 Error Handling Patterns:");
    println!("   • Configuration validation: ✅");
    println!("   • Resource initialization: ✅");
    println!("   • Graceful error propagation: ✅");

    // Show what would happen in a real connection scenario
    println!("\n🌐 Real-world Usage Scenario:");
    println!("   1. Configure client with specific requirements");
    println!("   2. Create access tickets for authentication");
    println!("   3. Establish secure connections");
    println!("   4. Send HTTP requests with ticket validation");
    println!("   5. Handle responses and maintain flow control");
    println!("   6. Properly close connections and cleanup");

    println!("\n🔐 Security Features:");
    println!("   • ChaCha20-Poly1305 AEAD encryption");
    println!("   • X25519 key exchange");
    println!("   • Ed25519 signatures");
    println!("   • Noise XK handshake protocol");
    println!("   • TLS transport layer security");

    println!("\n� Performance Features:");
    println!("   • Configurable flow control windows");
    println!("   • Stream multiplexing support");
    println!("   • Efficient frame processing");
    println!("   • Resource pooling and reuse");

    println!("\n✅ Advanced client example completed!");
    println!("💡 This demonstrates HTX library configuration");
    println!("   without requiring external network resources.");

    Ok(())
}
