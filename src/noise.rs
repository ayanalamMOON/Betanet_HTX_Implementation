use crate::{
    config::NoiseConfig,
    crypto::{export_tls_key, X25519KeyPair},
    error::{HtxError, Result},
    protocol::Role,
};
use snow::{Builder, HandshakeState, TransportState};
use tokio::time::Instant;

/// Noise XK handshake pattern for HTX inner layer
const NOISE_PATTERN: &str = "Noise_XK_25519_ChaChaPoly_SHA256";

/// Noise handshake and transport state
pub struct NoiseConnection {
    #[allow(dead_code)]
    role: Role,
    config: NoiseConfig,
    handshake_state: Option<HandshakeState>,
    transport_state: Option<TransportState>,
    local_keypair: Option<X25519KeyPair>,
    remote_public_key: Option<[u8; 32]>,
    last_key_update: Instant,
    bytes_sent: u64,
    bytes_received: u64,
    frames_sent: u32,
    frames_received: u32,
}

impl NoiseConnection {
    /// Create a new Noise connection as initiator (client)
    pub fn new_initiator(
        config: NoiseConfig,
        tls_exporter: &[u8],
        remote_static_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let local_keypair = X25519KeyPair::generate();

        // Derive K0 from TLS exporter
        let k0 = export_tls_key(tls_exporter, "htx inner v1", b"")?;

        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let private_key = local_keypair.private_bytes();
        let mut builder = builder.local_private_key(&private_key).psk(0, &k0[..32]); // Use first 32 bytes of K0 as PSK

        // Set remote static key if provided
        if let Some(ref remote_key) = remote_static_key {
            builder = builder.remote_public_key(remote_key);
        }

        let handshake_state = builder.build_initiator()?;

        // Note: set_remote_static not available in snow 0.9

        Ok(Self {
            role: Role::Client,
            config,
            handshake_state: Some(handshake_state),
            transport_state: None,
            local_keypair: Some(local_keypair),
            remote_public_key: remote_static_key,
            last_key_update: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            frames_received: 0,
        })
    }

    /// Create a new Noise connection as responder (server)
    pub fn new_responder(
        config: NoiseConfig,
        tls_exporter: &[u8],
        server_keypair: X25519KeyPair,
    ) -> Result<Self> {
        // Derive K0 from TLS exporter
        let k0 = export_tls_key(tls_exporter, "htx inner v1", b"")?;

        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let private_key = server_keypair.private_bytes();
        let handshake_state = builder
            .local_private_key(&private_key)
            .psk(0, &k0[..32]) // Use first 32 bytes of K0 as PSK
            .build_responder()?;

        Ok(Self {
            role: Role::Server,
            config,
            handshake_state: Some(handshake_state),
            transport_state: None,
            local_keypair: Some(server_keypair),
            remote_public_key: None,
            last_key_update: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            frames_received: 0,
        })
    }

    /// Process handshake message
    pub fn process_handshake_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>> {
        let handshake_state = self
            .handshake_state
            .as_mut()
            .ok_or_else(|| HtxError::Protocol("No handshake state".to_string()))?;

        let mut payload_buf = vec![0u8; 65535]; // Conservative size for payload

        // Read the incoming message
        let payload_len = handshake_state.read_message(message, &mut payload_buf)?;
        payload_buf.truncate(payload_len);

        // For server: check if handshake is complete after reading (server completes when receiving final message)
        if self.role == Role::Server && handshake_state.is_handshake_finished() {
            // Extract remote static key first, before consuming handshake_state
            if let Some(remote_key) = handshake_state.get_remote_static() {
                if remote_key.len() == 32 {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(remote_key);
                    self.remote_public_key = Some(key_bytes);
                }
            }

            // Take ownership and consume handshake_state
            let handshake_state = self.handshake_state.take().unwrap();
            let transport_state = handshake_state.into_transport_mode()?;
            self.transport_state = Some(transport_state);

            return Ok(None); // No response needed, handshake complete
        }

        // If handshake is not complete, we might need to send a response
        // Check if this handshake state expects to write a message next
        let should_write = match self.role {
            Role::Server => {
                // Server should respond after reading client's first message
                !handshake_state.is_handshake_finished()
            }
            Role::Client => {
                // Client needs to send final message after receiving server response
                !handshake_state.is_handshake_finished()
            }
        };

        if should_write {
            let mut response_buf = vec![0u8; 65535];
            // Write response message (empty payload for handshake)
            match handshake_state.write_message(b"", &mut response_buf) {
                Ok(response_len) => {
                    response_buf.truncate(response_len);

                    // Complete handshake after writing response (both client and server)
                    if handshake_state.is_handshake_finished() {
                        // Extract remote static key first, before consuming handshake_state
                        if let Some(remote_key) = handshake_state.get_remote_static() {
                            if remote_key.len() == 32 {
                                let mut key_bytes = [0u8; 32];
                                key_bytes.copy_from_slice(remote_key);
                                self.remote_public_key = Some(key_bytes);
                            }
                        }

                        // Take ownership and consume handshake_state
                        let handshake_state = self.handshake_state.take().unwrap();
                        let transport_state = handshake_state.into_transport_mode()?;
                        self.transport_state = Some(transport_state);
                    }

                    Ok(Some(response_buf))
                }
                Err(e) => Err(HtxError::Noise(e)),
            }
        } else {
            Ok(None)
        }
    }

    /// Generate next handshake message
    pub fn next_handshake_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let handshake_state = self
            .handshake_state
            .as_mut()
            .ok_or_else(|| HtxError::Protocol("No handshake state".to_string()))?;

        let mut message_buf = vec![0u8; 65535]; // Conservative size

        let len = handshake_state.write_message(payload, &mut message_buf)?;
        message_buf.truncate(len);

        // Check if handshake is complete
        if handshake_state.is_handshake_finished() {
            // Take ownership and consume handshake_state
            let handshake_state = self.handshake_state.take().unwrap();
            let transport_state = handshake_state.into_transport_mode()?;
            self.transport_state = Some(transport_state);
        }

        Ok(message_buf)
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.transport_state.is_some()
    }

    /// Encrypt a frame payload
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let transport_state = self
            .transport_state
            .as_mut()
            .ok_or_else(|| HtxError::Protocol("Handshake not complete".to_string()))?;

        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // Add space for auth tag
        let len = transport_state.write_message(plaintext, &mut ciphertext)?;
        ciphertext.truncate(len);

        // Update counters
        self.frames_sent += 1;
        self.bytes_sent += plaintext.len() as u64;

        // Check if key update is needed
        if self.should_update_keys() {
            self.initiate_key_update()?;
        }

        Ok(ciphertext)
    }

    /// Decrypt a frame payload
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let transport_state = self
            .transport_state
            .as_mut()
            .ok_or_else(|| HtxError::Protocol("Handshake not complete".to_string()))?;

        let mut plaintext = vec![0u8; ciphertext.len()]; // Decrypted will be smaller
        let len = transport_state.read_message(ciphertext, &mut plaintext)?;
        plaintext.truncate(len);

        // Update counters
        self.frames_received += 1;
        self.bytes_received += plaintext.len() as u64;

        Ok(plaintext)
    }

    /// Check if keys should be updated based on policy
    pub fn should_update_keys(&self) -> bool {
        let now = Instant::now();
        let time_since_update = now.duration_since(self.last_key_update);

        // Check all key update conditions from spec
        self.bytes_sent >= self.config.key_update_bytes
            || self.bytes_received >= self.config.key_update_bytes
            || self.frames_sent >= self.config.key_update_frames
            || self.frames_received >= self.config.key_update_frames
            || time_since_update >= self.config.key_update_time
    }

    /// Initiate key update process
    pub fn initiate_key_update(&mut self) -> Result<()> {
        let transport_state = self
            .transport_state
            .as_mut()
            .ok_or_else(|| HtxError::Protocol("Handshake not complete".to_string()))?;

        // Rekey the transport state (returns unit, no need for ?)
        transport_state.rekey_outgoing();
        transport_state.rekey_incoming();

        // Reset counters
        self.frames_sent = 0;
        self.frames_received = 0;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.last_key_update = Instant::now();

        tracing::debug!("Key update completed");
        Ok(())
    }

    /// Get the remote peer's static public key
    pub fn remote_public_key(&self) -> Option<[u8; 32]> {
        self.remote_public_key
    }

    /// Get the local static public key
    pub fn local_public_key(&self) -> Option<[u8; 32]> {
        self.local_keypair.as_ref().map(|kp| kp.public_bytes())
    }

    /// Get connection statistics
    pub fn stats(&self) -> NoiseStats {
        NoiseStats {
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            frames_sent: self.frames_sent,
            frames_received: self.frames_received,
            last_key_update: self.last_key_update,
            handshake_complete: self.is_handshake_complete(),
        }
    }
}

/// Noise connection statistics
#[derive(Debug, Clone)]
pub struct NoiseStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u32,
    pub frames_received: u32,
    pub last_key_update: Instant,
    pub handshake_complete: bool,
}

/// Post-quantum hybrid key exchange (X25519-Kyber768)
/// This will be required from 2027-01-01
#[cfg(feature = "post-quantum")]
pub mod post_quantum {
    use super::*;
    use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

    pub struct HybridKeyPair {
        x25519_keypair: X25519KeyPair,
        kyber_public: pqcrypto_kyber::kyber768::PublicKey,
        kyber_secret: pqcrypto_kyber::kyber768::SecretKey,
    }

    impl HybridKeyPair {
        pub fn generate() -> Self {
            let x25519_keypair = X25519KeyPair::generate();
            let (kyber_public, kyber_secret) = pqcrypto_kyber::kyber768::keypair();

            Self {
                x25519_keypair,
                kyber_public,
                kyber_secret,
            }
        }

        pub fn public_key_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&self.x25519_keypair.public_bytes());
            bytes.extend_from_slice(self.kyber_public.as_bytes());
            bytes
        }

        pub fn dh_and_encapsulate(&self, peer_public: &[u8]) -> Result<Vec<u8>> {
            if peer_public.len() < 32 {
                return Err(HtxError::Crypto("Invalid peer public key".to_string()));
            }

            // X25519 DH
            let x25519_shared = self.x25519_keypair.dh(&peer_public[..32])?;

            // Kyber768 encapsulation
            let kyber_public_bytes = &peer_public[32..];
            let kyber_public = pqcrypto_kyber::kyber768::PublicKey::from_bytes(kyber_public_bytes)
                .map_err(|e| HtxError::Crypto(format!("Invalid Kyber public key: {:?}", e)))?;

            let (ciphertext, kyber_shared) = pqcrypto_kyber::kyber768::encapsulate(&kyber_public);

            // Combine shared secrets
            let mut combined = Vec::new();
            combined.extend_from_slice(&x25519_shared);
            combined.extend_from_slice(&kyber_shared.as_bytes());
            combined.extend_from_slice(&ciphertext.as_bytes());

            Ok(combined)
        }

        pub fn dh_and_decapsulate(&self, dh_data: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
            if dh_data.len() != 32 {
                return Err(HtxError::Crypto("Invalid DH data length".to_string()));
            }

            // X25519 DH
            let x25519_shared = self.x25519_keypair.dh(dh_data)?;

            // Kyber768 decapsulation
            let kyber_ciphertext = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
                .map_err(|e| HtxError::Crypto(format!("Invalid Kyber ciphertext: {:?}", e)))?;

            let kyber_shared = pqcrypto_kyber::kyber768::decapsulate(
                &kyber_ciphertext,
                &self.kyber_keypair.secret,
            );

            // Combine shared secrets
            let mut combined = Vec::new();
            combined.extend_from_slice(&x25519_shared);
            combined.extend_from_slice(&kyber_shared.as_bytes());

            Ok(combined)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    #[test]
    fn test_noise_handshake() {
        let config = NoiseConfig::default();
        let tls_exporter = random_bytes(64);

        let server_keypair = X25519KeyPair::generate();
        let server_public = server_keypair.public_bytes();

        // Create client and server connections
        let mut client =
            NoiseConnection::new_initiator(config.clone(), &tls_exporter, Some(server_public))
                .unwrap();

        let mut server =
            NoiseConnection::new_responder(config, &tls_exporter, server_keypair).unwrap();

        // Perform handshake - Noise XK pattern
        assert!(!client.is_handshake_complete());
        assert!(!server.is_handshake_complete());

        // Step 1: Client -> Server (e)
        let msg1 = client.next_handshake_message(b"").unwrap();
        assert!(!client.is_handshake_complete()); // Not complete after first message

        // Step 2: Server processes and responds (e, ee, s, es)
        let msg2 = server.process_handshake_message(&msg1).unwrap();
        assert!(!server.is_handshake_complete()); // Server not complete until final message
        assert!(msg2.is_some(), "Server should send response message");

        // Step 3: Client processes server response and sends final message (s, se)
        let msg3 = client.process_handshake_message(&msg2.unwrap()).unwrap();
        assert!(msg3.is_some(), "Client should send final handshake message");
        assert!(
            client.is_handshake_complete(),
            "Client handshake should be complete after sending final message"
        );

        // Step 4: Server processes final message
        let final_response = server.process_handshake_message(&msg3.unwrap()).unwrap();
        assert!(
            final_response.is_none(),
            "Server should not send response after final message"
        );

        // Both should be complete now
        assert!(
            client.is_handshake_complete(),
            "Client handshake should be complete"
        );
        assert!(
            server.is_handshake_complete(),
            "Server handshake should be complete"
        );
    }

    #[test]
    fn test_noise_encryption() {
        let config = NoiseConfig::default();
        let tls_exporter = random_bytes(64);

        let server_keypair = X25519KeyPair::generate();
        let server_public = server_keypair.public_bytes();

        let mut client =
            NoiseConnection::new_initiator(config.clone(), &tls_exporter, Some(server_public))
                .unwrap();

        let mut server =
            NoiseConnection::new_responder(config, &tls_exporter, server_keypair).unwrap();

        // Complete handshake properly - Noise XK pattern
        // Step 1: Client -> Server (e)
        let msg1 = client.next_handshake_message(b"").unwrap();

        // Step 2: Server -> Client (e, ee, s, es)
        let msg2 = server.process_handshake_message(&msg1).unwrap().unwrap();

        // Step 3: Client -> Server (s, se)
        let msg3 = client.process_handshake_message(&msg2).unwrap().unwrap();

        // Step 4: Server processes final message
        server.process_handshake_message(&msg3).unwrap();

        // Verify handshake is complete before attempting encryption
        assert!(
            client.is_handshake_complete(),
            "Client handshake must be complete"
        );
        assert!(
            server.is_handshake_complete(),
            "Server handshake must be complete"
        );

        // Test encryption/decryption
        let plaintext = b"Hello, Betanet!";
        let ciphertext = client.encrypt(plaintext).unwrap();
        let decrypted = server.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_key_update_conditions() {
        let mut config = NoiseConfig::default();
        config.key_update_bytes = 100;
        config.key_update_frames = 5;
        config.key_update_time = std::time::Duration::from_millis(100);

        let tls_exporter = random_bytes(64);
        let server_keypair = X25519KeyPair::generate();
        let server_public = server_keypair.public_bytes();

        let mut client =
            NoiseConnection::new_initiator(config, &tls_exporter, Some(server_public)).unwrap();

        // Simulate sending frames
        client.frames_sent = 6;
        assert!(client.should_update_keys());

        // Reset
        client.frames_sent = 0;
        client.bytes_sent = 150;
        assert!(client.should_update_keys());
    }
}
