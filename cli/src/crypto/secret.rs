use crate::crypto::ratchet::SessionKeys;
use std::sync::Mutex;

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
