use crate::crypto::ratchet::SessionKeys;
use std::sync::Mutex;
use zeroize::Zeroize;

/// Upper bound on secret input length (bytes).
pub const SECRET_MAX: usize = 256;

/// Fixed-size, RAM-locked buffer for secrets (e.g. a typed passphrase).
///
/// The backing storage is a single allocation that is never reallocated, is
/// `mlock`ed so it cannot be swapped out, and is zeroized on drop.
pub struct SecretBuf {
    buf: Box<[u8; SECRET_MAX]>,
    len: usize,
}

impl SecretBuf {
    pub fn new() -> Self {
        let buf = Box::new([0u8; SECRET_MAX]);
        // SAFETY: pointer/length describe the live heap allocation owned by `buf`.
        // Best effort: mlockall may not be active yet (UI process, tests).
        unsafe { libc::mlock(buf.as_ptr() as *const _, SECRET_MAX) };
        Self { buf, len: 0 }
    }

    /// Appends a byte; returns `false` if the buffer is full.
    pub fn push(&mut self, b: u8) -> bool {
        if self.len == SECRET_MAX {
            return false;
        }
        self.buf[self.len] = b;
        self.len += 1;
        true
    }

    /// Removes the last byte, wiping its slot.
    pub fn pop(&mut self) {
        if self.len > 0 {
            self.len -= 1;
            self.buf[self.len] = 0;
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.buf.zeroize();
        // SAFETY: same allocation that was locked in `new`.
        unsafe { libc::munlock(self.buf.as_ptr() as *const _, SECRET_MAX) };
    }
}

/// Global centralized session storage for ZeroizeOnDrop on shutdown (D9).
pub static SESSION: Mutex<Option<SessionKeys>> = Mutex::new(None);

/// Stores the active session keys.
pub fn set_session(keys: SessionKeys) {
    let mut g = SESSION.lock().unwrap_or_else(|p| p.into_inner());
    *g = Some(keys);
}

/// Seals (encrypts and authenticates) a message using the active send ratchet chain.
///
/// # Errors
///
/// Returns an error if the session is not initialized or if encryption fails.
pub fn seal(pt: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut g = SESSION.lock().unwrap_or_else(|p| p.into_inner());
    match g.as_mut() {
        Some(s) => s.send.seal(pt),
        None => Err("session not initialized"),
    }
}

/// Opens (authenticates and decrypts) a message using the active recv ratchet chain.
///
/// # Errors
///
/// Returns an error if the session is not initialized or if decryption/authentication fails.
pub fn open(ct: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut g = SESSION.lock().unwrap_or_else(|p| p.into_inner());
    match g.as_mut() {
        Some(s) => s.recv.open(ct),
        None => Err("session not initialized"),
    }
}

/// Explicitly wipes and clears the session keys from memory.
#[allow(dead_code)]
pub fn wipe_session() {
    let mut g = match SESSION.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.take(); // ZeroizeOnDrop runs here
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secretbuf_push_pop_and_cap() {
        let mut s = SecretBuf::new();
        assert!(s.as_bytes().is_empty());
        for b in b"abc" {
            assert!(s.push(*b));
        }
        assert_eq!(s.as_bytes(), b"abc");
        s.pop();
        assert_eq!(s.as_bytes(), b"ab");
        assert_eq!(s.buf[2], 0, "popped slot must be wiped");
        while s.push(b'x') {}
        assert_eq!(s.as_bytes().len(), SECRET_MAX);
        assert!(!s.push(b'y'));
    }
    use crate::crypto::session::Role;

    #[test]
    fn test_secret_session_lifecycle_and_wipe() {
        let shared = [0x33u8; 32];
        let client_keys = SessionKeys::from_shared(&shared, Role::Initiator);
        let mut server_keys = SessionKeys::from_shared(&shared, Role::Responder);

        set_session(client_keys);

        // Test sealing from global SESSION
        let msg = b"secret session test message";
        let ct = seal(msg).expect("seal should succeed");

        // Server decrypts
        let pt = server_keys.recv.open(&ct).expect("open should succeed");
        assert_eq!(msg.to_vec(), pt);

        // Test opening via global SESSION
        let reply = b"server reply message";
        let ct_reply = server_keys.send.seal(reply).expect("server seal");
        let pt_reply = open(&ct_reply).expect("open via SESSION should succeed");
        assert_eq!(reply.to_vec(), pt_reply);

        // Wipe session
        wipe_session();

        // Further attempts must fail cleanly because session was wiped
        assert!(SESSION.lock().unwrap().is_none());
        assert_eq!(seal(b"fail").unwrap_err(), "session not initialized");
        assert_eq!(open(&ct_reply).unwrap_err(), "session not initialized");
    }
}
