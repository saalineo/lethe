use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub const NONCE_LEN: usize = 12;

pub fn seal(message_key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());

    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, plaintext).map_err(|_| "encryption failed")?;

    let mut out = Vec::with_capacity(NONCE_LEN + encrypted.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend(encrypted);
    Ok(out)
}

pub fn open(message_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() < NONCE_LEN {
        return Err("ciphertext too short");
    }
    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key));
    cipher.decrypt(nonce, ct).map_err(|_| "decryption failed")
}
