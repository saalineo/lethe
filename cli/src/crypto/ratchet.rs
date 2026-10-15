use super::cipher;
use super::kdf::derive_message_and_chain_keys;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Chain {
    chain_key: [u8; 32],
    #[zeroize(skip)]
    counter: u64,
}

impl Chain {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            chain_key: key,
            counter: 0,
        }
    }

    #[allow(dead_code)]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn seal(&mut self, pt: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (mk, next) = derive_message_and_chain_keys(&self.chain_key)?;
        let ct = cipher::seal(&mk, self.counter, pt)?;
        self.chain_key = *next;
        self.counter += 1;
        Ok(ct)
    }

    /// Any failure is fatal for the session: caller must tear down.
    /// Crucially verifies AEAD tag BEFORE advancing the ratchet chain (D6).
    pub fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (mk, next) = derive_message_and_chain_keys(&self.chain_key)?;
        let pt = cipher::open(&mk, self.counter, ct)?; // verify BEFORE advancing
        self.chain_key = *next;
        self.counter += 1;
        Ok(pt)
    }

    // Compatibility aliases
    pub fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.seal(pt)
    }

    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.open(ct)
    }
}

pub type RatchetState = Chain;

/// Holds directional session keys (D3).
#[derive(Zeroize)]
pub struct SessionKeys {
    pub send: Chain,
    pub recv: Chain,
}

impl SessionKeys {
    pub fn into_parts(self) -> (Chain, Chain) {
        (self.send, self.recv)
    }
    /// Derives directional chains based on node role (client vs server)
    pub fn from_shared_secret(shared_secret: &[u8; 32], is_server: bool) -> Result<Self, &'static str> {
        let hk = Hkdf::<Sha256>::new(Some(b"lethe-v2"), shared_secret);
        let mut k_c2s = Zeroizing::new([0u8; 32]);
        let mut k_s2c = Zeroizing::new([0u8; 32]);

        hk.expand(b"c2s", &mut *k_c2s)
            .map_err(|_| "HKDF expand failed for c2s")?;
        hk.expand(b"s2c", &mut *k_s2c)
            .map_err(|_| "HKDF expand failed for s2c")?;

        let (send_key, recv_key) = if is_server {
            (*k_s2c, *k_c2s) // Server sends s2c, receives c2s
        } else {
            (*k_c2s, *k_s2c) // Client sends c2s, receives s2c
        };

        Ok(Self {
            send: Chain::new(send_key),
            recv: Chain::new(recv_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directional_communication() {
        let shared_secret = [0x55u8; 32];
        let mut client_keys = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();
        let mut server_keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();

        let client_msg = b"hello from client";
        let ct_c2s = client_keys.send.seal(client_msg).unwrap();
        let decrypted_by_server = server_keys.recv.open(&ct_c2s).unwrap();
        assert_eq!(client_msg.to_vec(), decrypted_by_server);

        let server_msg = b"greetings from server";
        let ct_s2c = server_keys.send.seal(server_msg).unwrap();
        let decrypted_by_client = client_keys.recv.open(&ct_s2c).unwrap();
        assert_eq!(server_msg.to_vec(), decrypted_by_client);
    }

    #[test]
    fn test_distinct_keystreams_d3() {
        let shared_secret = [0x77u8; 32];
        let mut client_keys = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();
        let mut server_keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();

        let identical_msg = b"identical message at counter 0";
        let ct_client = client_keys.send.seal(identical_msg).unwrap();
        let ct_server = server_keys.send.seal(identical_msg).unwrap();

        // Nonce reuse check: Ciphertexts MUST be different because keys are distinct
        assert_ne!(ct_client, ct_server);
    }

    #[test]
    fn test_tampering_does_not_advance_chain_d6() {
        let shared_secret = [0x99u8; 32];
        let mut client_keys = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();
        let mut server_keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();

        let valid_msg = b"tamper test payload";
        let mut corrupted_ct = client_keys.send.seal(valid_msg).unwrap();
        // Flip one byte in ciphertext
        if let Some(b) = corrupted_ct.first_mut() {
            *b ^= 0xff;
        }

        // Decryption of corrupted payload must fail
        assert!(server_keys.recv.open(&corrupted_ct).is_err());

        // Counter must NOT have advanced
        assert_eq!(server_keys.recv.counter(), 0);

        // A valid message at counter 1 from client cannot be decrypted if server counter is 0,
        // but if client sends another valid message at the current counter, it works:
        // Here, test with a fresh valid message encrypted at counter 0:
        let mut fresh_client = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();
        let valid_ct = fresh_client.send.seal(valid_msg).unwrap();
        let pt = server_keys.recv.open(&valid_ct).unwrap();
        assert_eq!(valid_msg.to_vec(), pt);
        assert_eq!(server_keys.recv.counter(), 1);
    }
}
