#![no_main]
use libfuzzer_sys::fuzz_target;
use htx::frame::Frame;
use bytes::Bytes;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Test frame deserialization
    let _ = Frame::deserialize(Bytes::from(data.to_vec()));

    // Test frame creation and serialization
    if data.len() >= 8 {
        let stream_id = u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
        let payload = Bytes::from(data[8..].to_vec());

        let frame = Frame::stream(stream_id, payload);
        let _ = frame.serialize_header();
    }
});
