use std::io::{self, Read, Write};
use zeroize::Zeroizing;

use crate::crypto::ratchet::SessionKeys;

/// Communication role in SPAKE2 key agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client initiates SPAKE2 exchange.
    Initiator,
    /// Server responds to SPAKE2 exchange.
    Responder,
}

impl Role {
    #[allow(dead_code)]
    pub const fn is_server(self) -> bool {
        matches!(self, Role::Responder)
    }

    pub const fn from_is_server(is_server: bool) -> Self {
        if is_server {
            Role::Responder
        } else {
            Role::Initiator
        }
    }
}

/// Stretches a user passphrase into a 32-byte key using Argon2id.
///
/// Uses parameters: 64 MiB memory, 3 iterations, 1 lane.
/// A fixed domain-separated salt is used because the stretched output is only
/// used to feed the PAKE, never stored as an authentication verifier.
pub fn stretch(passphrase: &[u8]) -> Zeroizing<[u8; 32]> {
    // Fixed app-wide salt is acceptable here: the output only feeds a PAKE, never a verifier.
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).expect("valid Argon2id parameters"); // 64 MiB, t=3
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(passphrase, b"lethe/v2/passphrase", &mut *out)
        .expect("Argon2id hashing failed");
    out
}

/// Executes SPAKE2 key agreement with mutual HMAC key confirmation.
///
/// # Errors
///
/// Returns an [`io::Error`] if the underlying stream I/O fails, if the PAKE exchange fails,
/// or if key confirmation fails (e.g., due to mismatched passphrases).
pub fn agree<S: Read + Write>(io: &mut S, role: Role, pw: &[u8; 32]) -> io::Result<SessionKeys> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use spake2::{Ed25519Group, Identity, Password, Spake2};

    type HmacSha256 = Hmac<Sha256>;

    // Cell size, tick and version are part of the transcript: peers with
    // mismatched parameters fail key agreement instead of desyncing.
    let id_c = crate::proto::params::bound_identity(b"lethe-client");
    let id_s = crate::proto::params::bound_identity(b"lethe-server");

    let (state, msg) = match role {
        Role::Initiator => Spake2::<Ed25519Group>::start_a(
            &Password::new(pw),
            &Identity::new(&id_c),
            &Identity::new(&id_s),
        ),
        Role::Responder => Spake2::<Ed25519Group>::start_b(
            &Password::new(pw),
            &Identity::new(&id_c),
            &Identity::new(&id_s),
        ),
    };
    io.write_all(&msg)?; // msg is 33 bytes
    io.flush()?;

    let mut peer = Zeroizing::new([0u8; 33]);
    io.read_exact(&mut *peer)?;
    let shared = Zeroizing::new(
        state
            .finish(&*peer)
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "pake"))?,
    );

    let compute_confirm = |label: &[u8]| -> io::Result<Zeroizing<[u8; 32]>> {
        let mut mac = HmacSha256::new_from_slice(&shared)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        mac.update(label);
        let tag = mac.finalize().into_bytes();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&tag);
        Ok(out)
    };

    let confirm_c2s = compute_confirm(b"confirm-c2s")?;
    let confirm_s2c = compute_confirm(b"confirm-s2c")?;

    match role {
        Role::Initiator => {
            // Client sends confirm-c2s first
            io.write_all(&*confirm_c2s)?;
            io.flush()?;

            // Client receives and verifies confirm-s2c
            let mut peer_confirm = Zeroizing::new([0u8; 32]);
            io.read_exact(&mut *peer_confirm)?;

            let mut mac = HmacSha256::new_from_slice(&shared)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            mac.update(b"confirm-s2c");
            mac.verify_slice(&*peer_confirm).map_err(|_| {
                io::Error::new(io::ErrorKind::PermissionDenied, "key confirmation failed")
            })?;
        }
        Role::Responder => {
            // Server receives and verifies confirm-c2s first
            let mut peer_confirm = Zeroizing::new([0u8; 32]);
            io.read_exact(&mut *peer_confirm)?;

            let mut mac = HmacSha256::new_from_slice(&shared)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            mac.update(b"confirm-c2s");
            mac.verify_slice(&*peer_confirm).map_err(|_| {
                io::Error::new(io::ErrorKind::PermissionDenied, "key confirmation failed")
            })?;

            // Server responds with confirm-s2c
            io.write_all(&*confirm_s2c)?;
            io.flush()?;
        }
    }

    Ok(SessionKeys::from_shared(&shared, role))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[test]
    fn test_stretch() {
        let pw = stretch(b"test_password");
        assert_ne!(*pw, [0u8; 32]);
    }

    #[test]
    fn test_agree_success() {
        let (mut s1, mut s2) = UnixStream::pair().unwrap();
        let pw = [42u8; 32];

        let handle = thread::spawn(move || agree(&mut s2, Role::Responder, &pw).unwrap());

        let mut client_keys = agree(&mut s1, Role::Initiator, &pw).unwrap();
        let mut server_keys = handle.join().unwrap();

        // Client encrypts, Server decrypts
        let msg = b"spake2 key agreement test";
        let ct = client_keys.send.seal(msg).unwrap();
        let pt = server_keys.recv.open(&ct).unwrap();
        assert_eq!(msg.to_vec(), pt);

        // Server encrypts, Client decrypts
        let reply = b"session keys work both ways";
        let ct_reply = server_keys.send.seal(reply).unwrap();
        let pt_reply = client_keys.recv.open(&ct_reply).unwrap();
        assert_eq!(reply.to_vec(), pt_reply);
    }

    #[test]
    fn test_agree_mismatched_password_fails_confirmation() {
        let (mut s1, mut s2) = UnixStream::pair().unwrap();
        let pw1 = [42u8; 32];
        let pw2 = [99u8; 32];

        let handle = thread::spawn(move || agree(&mut s2, Role::Responder, &pw2));

        let client_res = agree(&mut s1, Role::Initiator, &pw1);
        let server_res = handle.join().unwrap();

        // Server should fail key confirmation with PermissionDenied
        assert!(server_res.is_err());
        assert_eq!(
            server_res.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        // Client should also fail (either confirmation or unexpected EOF)
        assert!(client_res.is_err());
    }

    #[test]
    fn test_agree_over_transport_handle() {
        let lib_candidates = [
            "target/debug/liblethe.so",
            "../target/debug/liblethe.so",
            "target/release/liblethe.so",
            "../target/release/liblethe.so",
        ];
        let lib_path = match lib_candidates
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        {
            Some(p) => *p,
            None => return, // Skip if shared library not built yet
        };

        // Pick an unused local port
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // Free the port so StartNode can bind

        let addr = format!("127.0.0.1:{}", port);
        let pw = [123u8; 32];
        let addr_clone = addr.clone();

        let server_thread = thread::spawn(move || {
            let transport =
                crate::ffi::transport::TransportHandle::load(lib_path, true, &addr_clone).unwrap();
            let mut io = transport.io();
            let keys = agree(&mut io, Role::Responder, &pw).unwrap();
            drop(io);
            (transport, keys)
        });

        // Small delay to ensure server started listening
        thread::sleep(std::time::Duration::from_millis(50));

        let client_transport =
            crate::ffi::transport::TransportHandle::load(lib_path, false, &addr).unwrap();
        let mut client_io = client_transport.io();
        let mut client_keys = agree(&mut client_io, Role::Initiator, &pw).unwrap();

        let (_server_transport, mut server_keys) = server_thread.join().unwrap();

        let msg = b"full end-to-end transport + spake2 agreement";
        let ct = client_keys.send.seal(msg).unwrap();
        let pt = server_keys.recv.open(&ct).unwrap();
        assert_eq!(msg.to_vec(), pt);

        let reply = b"transport confirmed both directions";
        let ct_rep = server_keys.send.seal(reply).unwrap();
        let pt_rep = client_keys.recv.open(&ct_rep).unwrap();
        assert_eq!(reply.to_vec(), pt_rep);
    }
}
