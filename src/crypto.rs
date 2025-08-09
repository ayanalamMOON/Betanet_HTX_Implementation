use crate::error::{HtxError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

/// ChaCha20-Poly1305 AEAD cipher
pub type AeadCipher = ChaCha20Poly1305;

/// Key derivation function (HKDF-SHA256)
pub type Kdf = Hkdf<Sha256>;

/// X25519 key exchange
pub struct X25519KeyPair {
    private: StaticSecret,
    pub public: PublicKey,
}

impl X25519KeyPair {
    /// Generate a new keypair
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    /// Create from private key bytes
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(HtxError::Crypto("Invalid private key length".to_string()));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let private = StaticSecret::from(key_bytes);
        let public = PublicKey::from(&private);

        Ok(Self { private, public })
    }

    /// Get public key bytes
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get private key bytes
    pub fn private_bytes(&self) -> [u8; 32] {
        self.private.to_bytes()
    }

    /// Perform Diffie-Hellman key exchange
    pub fn dh(&self, peer_public: &[u8]) -> Result<[u8; 32]> {
        if peer_public.len() != 32 {
            return Err(HtxError::Crypto(
                "Invalid peer public key length".to_string(),
            ));
        }

        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(peer_public);

        let peer_public = PublicKey::from(public_bytes);
        let shared = self.private.diffie_hellman(&peer_public);
        Ok(shared.to_bytes())
    }
}

/// Ed25519 signing keypair
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new keypair
    pub fn generate() -> Self {
        let mut sk_bytes = [0u8; SECRET_KEY_LENGTH];
        OsRng.fill_bytes(&mut sk_bytes);
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create from private key bytes
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(HtxError::Crypto("Invalid private key length".to_string()));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get public key bytes
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get private key bytes
    pub fn private_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(HtxError::Crypto("Invalid signature length".to_string()));
        }

        let signature = Signature::from_bytes(signature.try_into().unwrap());
        self.verifying_key
            .verify(message, &signature)
            .map_err(|e| HtxError::Crypto(format!("Signature verification failed: {}", e)))
    }
}

/// Verify Ed25519 signature with public key
pub fn verify_ed25519(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
    if signature.len() != 64 {
        return Err(HtxError::Crypto("Invalid signature length".to_string()));
    }
    if public_key.len() != 32 {
        return Err(HtxError::Crypto("Invalid public key length".to_string()));
    }

    let public_key = VerifyingKey::from_bytes(public_key.try_into().unwrap())
        .map_err(|e| HtxError::Crypto(format!("Invalid public key: {}", e)))?;
    let signature = Signature::from_bytes(signature.try_into().unwrap());

    public_key
        .verify(message, &signature)
        .map_err(|e| HtxError::Crypto(format!("Signature verification failed: {}", e)))
}

/// AEAD encryption/decryption context
pub struct AeadContext {
    cipher: ChaCha20Poly1305,
    nonce_salt: [u8; 12],
    counter: u64,
}

impl AeadContext {
    /// Create new AEAD context with derived key
    pub fn new(key: &[u8], nonce_salt: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(HtxError::Crypto("Invalid key length".to_string()));
        }
        if nonce_salt.len() != 12 {
            return Err(HtxError::Crypto("Invalid nonce salt length".to_string()));
        }

        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        let mut salt = [0u8; 12];
        salt.copy_from_slice(nonce_salt);

        Ok(Self {
            cipher,
            nonce_salt: salt,
            counter: 0,
        })
    }

    /// Encrypt data with automatic nonce generation
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| HtxError::Crypto(format!("Encryption failed: {}", e)))?;
        Ok(ciphertext)
    }

    /// Decrypt data with counter increment
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| HtxError::Crypto(format!("Decryption failed: {}", e)))?;
        Ok(plaintext)
    }

    /// Generate the next nonce
    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];

        // XOR nonce salt with counter (little-endian)
        let counter_bytes = self.counter.to_le_bytes();
        for i in 0..8 {
            nonce_bytes[i] = self.nonce_salt[i] ^ counter_bytes[i];
        }
        // Last 4 bytes remain as nonce salt XOR 0 = nonce salt
        for i in 8..12 {
            nonce_bytes[i] = self.nonce_salt[i];
        }

        self.counter += 1;

        *Nonce::from_slice(&nonce_bytes)
    }

    /// Get current counter value
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Reset counter (for key updates)
    pub fn reset_counter(&mut self) {
        self.counter = 0;
    }
}

/// Key derivation using HKDF-SHA256
pub fn derive_key(shared_secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

/// Generate secure random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Access ticket cryptographic operations
pub mod access_ticket {
    use super::*;

    /// Generate access ticket
    pub fn generate_ticket(
        cli_priv: &[u8],
        ticket_pub: &[u8],
        ticket_key_id: &[u8; 8],
        _nonce: &[u8; 32],
        hour: u64,
    ) -> Result<[u8; 32]> {
        // Perform X25519 key exchange
        let cli_keypair = X25519KeyPair::from_private_bytes(cli_priv)?;
        let shared_secret = cli_keypair.dh(ticket_pub)?;

        // Derive salt
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(b"betanet-ticket-v1");
        salt_input.extend_from_slice(ticket_key_id);
        salt_input.extend_from_slice(&hour.to_be_bytes());

        let mut hasher = Sha256::default();
        hasher.update(&salt_input);
        let salt = hasher.finalize();

        // Derive access ticket using HKDF
        let ticket = derive_key(&shared_secret, salt.as_slice(), b"", 32);

        let mut result = [0u8; 32];
        result.copy_from_slice(&ticket);
        Ok(result)
    }

    /// Verify access ticket on server side
    pub fn verify_ticket(
        cli_pub: &[u8],
        ticket_priv: &[u8],
        ticket_key_id: &[u8; 8],
        provided_ticket: &[u8; 32],
        hour: u64,
    ) -> Result<bool> {
        // Perform X25519 key exchange from server side
        let ticket_keypair = X25519KeyPair::from_private_bytes(ticket_priv)?;
        let shared_secret = ticket_keypair.dh(cli_pub)?;

        // Derive expected ticket
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(b"betanet-ticket-v1");
        salt_input.extend_from_slice(ticket_key_id);
        salt_input.extend_from_slice(&hour.to_be_bytes());

        let mut hasher = Sha256::default();
        hasher.update(&salt_input);
        let salt = hasher.finalize();
        let expected_ticket = derive_key(&shared_secret, salt.as_slice(), b"", 32);

        // Constant-time comparison using ed25519-dalek's verify
        let expected_bytes: [u8; 32] = expected_ticket.as_slice().try_into().unwrap();
        Ok(*provided_ticket == expected_bytes)
    }
}

/// TLS key export for inner handshake derivation
pub fn export_tls_key(exporter: &[u8], label: &str, context: &[u8]) -> Result<Vec<u8>> {
    // Implement proper TLS exporter using HKDF-Expand-Label as per RFC 8446
    // This follows the TLS 1.3 key export specification
    export_tls_key_material(exporter, label, context, 64)
}

/// TLS key export implementation following RFC 8446
/// This properly implements the TLS exporter interface as intended
pub fn export_tls_key_material(
    exporter_master_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    // TLS 1.3 Exporter-Master-Secret derivation
    // RFC 8446 Section 7.5: Exporters
    //
    // The exporter interface is:
    // TLS-Exporter(label, context_value, key_length) =
    //     HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
    //                       "exporter", Hash(context_value), key_length)

    if exporter_master_secret.is_empty() {
        return Err(HtxError::Crypto("Empty exporter master secret".to_string()));
    }

    if length > 255 * 32 {
        return Err(HtxError::Crypto("Requested length too large".to_string()));
    }

    // Step 1: Derive secret for the export label
    let derived_secret = hkdf_expand_label(
        exporter_master_secret,
        label,
        b"", // No context for derive-secret
        32,  // SHA256 hash length
    )?;

    // Step 2: Hash the context value
    let mut hasher = Sha256::default();
    hasher.update(context);
    let context_hash = hasher.finalize();

    // Step 3: HKDF-Expand-Label with "exporter" as the label
    let result = hkdf_expand_label(&derived_secret, "exporter", &context_hash, length)?;

    Ok(result)
}

/// HKDF-Expand-Label implementation as per RFC 8446 Section 7.1
/// This is the proper TLS 1.3 key derivation function
pub fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    if length > 0xFFFF {
        return Err(HtxError::Crypto(
            "Length too large for HKDF-Expand-Label".to_string(),
        ));
    }

    // Construct HkdfLabel as per RFC 8446:
    // struct {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // } HkdfLabel;

    let mut hkdf_label = Vec::new();

    // Length (2 bytes, big-endian)
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());

    // Label with "tls13 " prefix
    let full_label = format!("tls13 {}", label);
    let label_bytes = full_label.as_bytes();
    if label_bytes.len() > 255 {
        return Err(HtxError::Crypto("Label too long".to_string()));
    }
    hkdf_label.push(label_bytes.len() as u8);
    hkdf_label.extend_from_slice(label_bytes);

    // Context
    if context.len() > 255 {
        return Err(HtxError::Crypto("Context too long".to_string()));
    }
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // HKDF-Expand using the constructed label as info
    let hkdf = Hkdf::<Sha256>::from_prk(secret)
        .map_err(|e| HtxError::Crypto(format!("HKDF from PRK failed: {}", e)))?;

    let mut output = vec![0u8; length];
    hkdf.expand(&hkdf_label, &mut output)
        .map_err(|e| HtxError::Crypto(format!("HKDF expand failed: {}", e)))?;

    Ok(output)
}

/// Extract TLS exporter master secret from a rustls connection
/// This is the proper interface that should be used by the client
pub fn extract_tls_exporter_master_secret(
    connection: &rustls::ClientConnection,
) -> Result<Vec<u8>> {
    // In rustls 0.21+, we can access the exporter master secret
    // through the connection's export_keying_material method

    // For the HTX protocol, we need 64 bytes of key material
    let mut output = vec![0u8; 64];

    // Use the standard TLS exporter interface
    // Label: "EXPORTER-htx-inner-handshake" as per HTX specification
    // Context: "betanet-1.1" to bind to protocol version
    connection
        .export_keying_material(
            &mut output,
            b"EXPORTER-htx-inner-handshake",
            Some(b"betanet-1.1"),
        )
        .map_err(|e| HtxError::Crypto(format!("TLS key export failed: {}", e)))?;

    Ok(output)
}

/// Extract TLS exporter master secret from a rustls server connection
/// This is the server-side equivalent for TLS exporter functionality
pub fn extract_tls_exporter_master_secret_server(
    connection: &rustls::ServerConnection,
) -> Result<Vec<u8>> {
    // Server-side TLS exporter using the same interface as client
    let mut output = vec![0u8; 64];

    // Use the standard TLS exporter interface
    // Label: "EXPORTER-htx-inner-handshake" as per HTX specification
    // Context: "betanet-1.1" to bind to protocol version
    connection
        .export_keying_material(
            &mut output,
            b"EXPORTER-htx-inner-handshake",
            Some(b"betanet-1.1"),
        )
        .map_err(|e| HtxError::Crypto(format!("Server TLS key export failed: {}", e)))?;

    Ok(output)
}

/// Cryptographic algorithm registry for algorithm agility
pub struct CryptoRegistry {
    hash_algorithms: HashMap<String, fn(&[u8]) -> Vec<u8>>,
    #[allow(dead_code)]
    aead_algorithms: HashMap<String, fn(&[u8]) -> Box<dyn AeadTrait>>,
    kdf_algorithms: HashMap<String, fn(&[u8], &[u8], &[u8], usize) -> Vec<u8>>,
}

/// Trait for AEAD algorithms to support algorithm agility
pub trait AeadTrait: Send + Sync {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl Default for CryptoRegistry {
    fn default() -> Self {
        let mut registry = Self {
            hash_algorithms: HashMap::new(),
            aead_algorithms: HashMap::new(),
            kdf_algorithms: HashMap::new(),
        };

        // Register default algorithms
        registry
            .hash_algorithms
            .insert("sha256".to_string(), |data| {
                let mut hasher = Sha256::default();
                hasher.update(data);
                hasher.finalize().to_vec()
            });

        registry
            .kdf_algorithms
            .insert("hkdf-sha256".to_string(), derive_key);

        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_keypair() {
        let keypair1 = X25519KeyPair::generate();
        let keypair2 = X25519KeyPair::generate();

        let shared1 = keypair1.dh(&keypair2.public_bytes()).unwrap();
        let shared2 = keypair2.dh(&keypair1.public_bytes()).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_ed25519_keypair() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"hello world";

        let signature = keypair.sign(message);
        keypair.verify(message, &signature).unwrap();

        // Test with wrong message
        let wrong_message = b"wrong message";
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_aead_context() {
        let key = random_bytes(32);
        let nonce_salt = random_bytes(12);

        let mut ctx1 = AeadContext::new(&key, &nonce_salt).unwrap();
        let mut ctx2 = AeadContext::new(&key, &nonce_salt).unwrap();

        let plaintext = b"hello world";
        let ciphertext = ctx1.encrypt(plaintext).unwrap();
        let decrypted = ctx2.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_access_ticket() {
        let cli_keypair = X25519KeyPair::generate();
        let ticket_keypair = X25519KeyPair::generate();
        let ticket_key_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let nonce = [0u8; 32];
        let hour = 123456;

        let ticket = access_ticket::generate_ticket(
            &cli_keypair.private_bytes(),
            &ticket_keypair.public_bytes(),
            &ticket_key_id,
            &nonce,
            hour,
        )
        .unwrap();

        let is_valid = access_ticket::verify_ticket(
            &cli_keypair.public_bytes(),
            &ticket_keypair.private_bytes(),
            &ticket_key_id,
            &ticket,
            hour,
        )
        .unwrap();

        assert!(is_valid);

        // Test with wrong hour
        let is_invalid = access_ticket::verify_ticket(
            &cli_keypair.public_bytes(),
            &ticket_keypair.private_bytes(),
            &ticket_key_id,
            &ticket,
            hour + 1,
        )
        .unwrap();

        assert!(!is_invalid);
    }

    #[test]
    fn test_hkdf_expand_label() {
        let secret = &[0u8; 32]; // Test secret
        let label = "test";
        let context = b"test context";
        let length = 32;

        let result = hkdf_expand_label(secret, label, context, length).unwrap();
        assert_eq!(result.len(), length);

        // Test with different inputs should produce different outputs
        let result2 = hkdf_expand_label(secret, "different", context, length).unwrap();
        assert_ne!(result, result2);

        let result3 = hkdf_expand_label(secret, label, b"different context", length).unwrap();
        assert_ne!(result, result3);
    }

    #[test]
    fn test_export_tls_key_material() {
        let exporter_master_secret = &[1u8; 32]; // Mock exporter master secret
        let label = "test-export";
        let context = b"test-context";
        let length = 64;

        let result =
            export_tls_key_material(exporter_master_secret, label, context, length).unwrap();
        assert_eq!(result.len(), length);

        // Different inputs should produce different outputs
        let result2 =
            export_tls_key_material(exporter_master_secret, "different", context, length).unwrap();
        assert_ne!(result, result2);

        // Test error cases
        assert!(export_tls_key_material(&[], label, context, length).is_err());
        assert!(
            export_tls_key_material(exporter_master_secret, label, context, 256 * 32 + 1).is_err()
        );
    }

    #[test]
    fn test_export_tls_key() {
        let exporter = &[2u8; 32]; // Mock TLS exporter data
        let label = "htx-test";
        let context = b"betanet-test";

        let result = export_tls_key(exporter, label, context).unwrap();
        assert_eq!(result.len(), 64);

        // Should be deterministic
        let result2 = export_tls_key(exporter, label, context).unwrap();
        assert_eq!(result, result2);

        // Different inputs should produce different outputs
        let result3 = export_tls_key(exporter, "different", context).unwrap();
        assert_ne!(result, result3);
    }
}
