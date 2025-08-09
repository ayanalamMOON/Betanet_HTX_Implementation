#![no_main]
use htx::config::NoiseConfig;
use htx::{crypto::X25519KeyPair, noise::NoiseConnection};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 128 {
        return;
    }

    let config = NoiseConfig::default();
    let tls_exporter = &data[0..64];

    // Generate server keypair
    let server_keypair = X25519KeyPair::generate();
    let server_public = server_keypair.public_bytes();

    // Try to create noise connections
    if let Ok(mut client) =
        NoiseConnection::new_initiator(config.clone(), tls_exporter, Some(server_public))
    {
        if let Ok(mut server) = NoiseConnection::new_responder(config, tls_exporter, server_keypair)
        {
            // Try handshake with fuzzed data
            let handshake_data = &data[64..];
            if handshake_data.len() > 0 {
                let _ = client.next_handshake_message(
                    &handshake_data[..std::cmp::min(32, handshake_data.len())],
                );

                if handshake_data.len() > 32 {
                    let _ = server.process_handshake_message(
                        &handshake_data[32..std::cmp::min(64, handshake_data.len())],
                    );
                }
            }
        }
    }
});
