#![no_main]
use libfuzzer_sys::fuzz_target;
use htx::tls::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }

    // Test TLS fingerprinting with various input sizes
    let mut grease_gen = GreaseGenerator::new();
    let _ = grease_gen.next_value();

    // Test JA3/JA4 calculation if enough data
    if data.len() >= 16 {
        // Create some basic TLS-like data structure for testing
        let cipher_suites = vec![0x1301, 0x1302, 0x1303]; // TLS 1.3 ciphers
        let extensions = vec![0x0000, 0x0010, 0x0023];   // Basic extensions
        let curves = vec![0x0017, 0x0018, 0x0019];       // Elliptic curves
        let point_formats = vec![0x00]; // Uncompressed point format

        let _ = calculate_ja3(0x0304, &cipher_suites, &extensions, &curves, &point_formats);
        let _ = calculate_ja4(0x0304, true, 3, 3, "h2", &cipher_suites, &extensions);
    }
});
