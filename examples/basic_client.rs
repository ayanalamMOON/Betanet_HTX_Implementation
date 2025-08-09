//! Basic HTX Client Example
//!
//! This example demonstrates how to create and use an HTX client
//! for secure communication.

use htx::{AccessTicket, Config, HtxClient, Result};
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting HTX Client Example");

    // Create client configuration
    let mut config = Config::default();

    // Set up access ticket keys (in real usage, these would be provided by server)
    let ticket_keypair = htx::crypto::X25519KeyPair::generate();
    config.access_ticket.ticket_public_key = Some(ticket_keypair.public_bytes());
    config.access_ticket.ticket_private_key = Some(ticket_keypair.private_bytes());

    // Create the HTX client
    println!("📡 Creating HTX client...");
    let _client = HtxClient::new(config.clone()).await?;

    // Create an access ticket for authentication
    let target_length = 128; // Target ticket size in bytes
    let (_access_ticket, _client_keypair) =
        AccessTicket::new(&config.access_ticket, target_length)?;

    println!("✅ Client created successfully!");
    println!("🎫 Access ticket generated ({} bytes)", target_length);

    // Show what the client is configured for
    println!("\n� Client Configuration:");
    println!("   • Transport: TCP with automatic port binding");
    println!("   • Security: ChaCha20-Poly1305 encryption");
    println!("   • Protocol: Noise XK handshake");
    println!("   • Authentication: Access ticket support");

    println!("\n🌐 Usage Scenarios:");
    println!("   • Connect to HTX servers on port 443");
    println!("   • Send HTTP requests with authentication");
    println!("   • Receive and process responses");
    println!("   • Maintain secure, encrypted communication");

    println!("\n🔧 Next Steps:");
    println!("   To use this client in production:");
    println!("   1. Configure target server address");
    println!("   2. Establish connection using dial()");
    println!("   3. Open streams for communication");
    println!("   4. Send/receive data securely");
    println!("   5. Handle errors and cleanup properly");

    println!("\n✅ Basic client example completed successfully!");

    Ok(())
}
