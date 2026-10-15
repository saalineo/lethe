use super::cipher;
use super::kdf::derive_message_and_chain_keys;
use zeroize::Zeroize;

pub struct RatchetState {
    chain_key: [u8; 32],
    send_count: u64,
    _recv_count: u64,
}

impl RatchetState {
    pub fn new(root_key: [u8; 32]) -> Self {
        Self {
            chain_key: root_key,
            send_count: 0,
            _recv_count: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (message_key, mut next_chain_key) = derive_message_and_chain_keys(&self.chain_key)?;
        self.chain_key = next_chain_key;
        let mut msg_key = message_key;
        let ct = cipher::seal(&msg_key, self.send_count, plaintext)?;
        self.send_count += 1;

        msg_key.zeroize();
        next_chain_key.zeroize();

        Ok(ct)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (message_key, mut next_chain_key) = derive_message_and_chain_keys(&self.chain_key)?;
        self.chain_key = next_chain_key;
        let mut msg_key = message_key;
        let pt = cipher::open(&msg_key, ciphertext)?;
        self._recv_count += 1;

        msg_key.zeroize();
        next_chain_key.zeroize();

        Ok(pt)
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let mut send_ratchet = RatchetState::new(key);
        let mut recv_ratchet = RatchetState::new(key);

        let msg = b"Hello Ratchet!";
        let ct = send_ratchet.encrypt(msg).unwrap();
        let pt = recv_ratchet.decrypt(&ct).unwrap();
        assert_eq!(msg.to_vec(), pt);
    }
}
