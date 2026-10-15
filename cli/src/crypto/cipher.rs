use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub const NONCE_LEN: usize = 12;

pub fn nonce_for(counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

pub fn seal(key: &[u8; 32], counter: u64, pt: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = nonce_for(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(nonce, pt).map_err(|_| "seal failed")
}

pub fn open(key: &[u8; 32], counter: u64, ct: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = nonce_for(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|_| "decryption failed")
}
