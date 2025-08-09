#![no_main]
use libfuzzer_sys::fuzz_target;
use htx::{Config, access_ticket::AccessTicket};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    // Create a test config with fuzzed ticket keys
    let mut config = Config::default();
    let mut ticket_pub = [0u8; 32];
    let mut ticket_priv = [0u8; 32];
    ticket_pub.copy_from_slice(&data[0..32]);
    ticket_priv.copy_from_slice(&data[32..64]);

    config.access_ticket.ticket_public_key = Some(ticket_pub);
    config.access_ticket.ticket_private_key = Some(ticket_priv);

    // Test access ticket generation
    let target_length = (data.len() % 128) + 64; // Reasonable range
    let _ = AccessTicket::new(&config.access_ticket, target_length);
});
