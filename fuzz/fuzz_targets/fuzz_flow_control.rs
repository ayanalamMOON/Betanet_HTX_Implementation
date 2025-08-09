#![no_main]
use libfuzzer_sys::fuzz_target;
use htx::flow_control::FlowControlManager;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let initial_window = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if initial_window == 0 {
        return;
    }

    let (manager, _updates) = FlowControlManager::new(initial_window);

    let stream_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if stream_id == 0 {
        return;
    }

    // Test flow control operations
    let _ = manager.create_stream(stream_id);

    // Process data with various sizes
    for chunk in data[8..].chunks(4) {
        if chunk.len() == 4 {
            let bytes = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if bytes > 0 && bytes < 1_000_000 { // Reasonable bounds
                let _ = manager.process_received_data(stream_id, bytes);
            }
        }
    }
});
