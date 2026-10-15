use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn client(stream: &mut TcpStream, auth_key: &[u8; 32]) -> io::Result<()> {
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let mut nonce = [0u8; 32];
    let mut payload = [0u8; 64];

    let result = (|| {
        getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other("rng failure"))?;

        let mut mac = HmacSha256::new_from_slice(auth_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        mac.update(&nonce);
        let signature = mac.finalize().into_bytes();

        payload[..32].copy_from_slice(&nonce);
        payload[32..].copy_from_slice(&signature);

        stream.write_all(&payload)?;
        stream.flush()?;
        Ok(())
    })();

    nonce.zeroize();
    payload.zeroize();
    let _ = stream.set_write_timeout(None);

    result
}

pub fn server(stream: &mut TcpStream, auth_key: &[u8; 32]) -> io::Result<()> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let mut payload = [0u8; 64];

    let result = (|| {
        stream.read_exact(&mut payload)?;

        let nonce = &payload[..32];
        let signature = &payload[32..];

        let mut mac = HmacSha256::new_from_slice(auth_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        mac.update(nonce);

        mac.verify_slice(signature)
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "invalid auth"))?;
        Ok(())
    })();

    payload.zeroize();
    let _ = stream.set_read_timeout(None);

    result
}
