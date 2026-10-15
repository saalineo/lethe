//! Minimal fixed-header IPC between the core and the sandboxed UI.
//!
//! `frame := tag:u8 | len:u16le | bytes[len]` with `len <= MAX_FRAME`.
//! Carried over an anonymous `socketpair`; no serde, no filesystem path.

use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 4096;
pub const HDR_LEN: usize = 3;

/// UI -> core.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UiToCore {
    /// One chat line (arbitrary bytes, not necessarily UTF-8).
    Line = 1,
    /// User asked to leave.
    Quit = 2,
    /// Chosen alias, sent once after start-up.
    Hello = 3,
}

/// Core -> UI.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoreToUi {
    /// A message from the peer.
    Peer = 1,
    /// A status line to show the user.
    Status = 2,
    /// Terminate now.
    Shutdown = 3,
    /// Handshake finished: UI may take over the terminal.
    Ready = 4,
}

pub fn send<W: Write>(s: &mut W, tag: u8, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipc frame too large"));
    }
    let mut frame = [0u8; HDR_LEN + MAX_FRAME];
    frame[0] = tag;
    frame[1..3].copy_from_slice(&(body.len() as u16).to_le_bytes());
    frame[HDR_LEN..HDR_LEN + body.len()].copy_from_slice(body);
    // Single write so concurrent senders sharing a lock never interleave headers.
    s.write_all(&frame[..HDR_LEN + body.len()])
}

pub fn recv<R: Read>(s: &mut R, buf: &mut [u8; MAX_FRAME]) -> io::Result<(u8, usize)> {
    let mut hdr = [0u8; HDR_LEN];
    s.read_exact(&mut hdr)?;
    let len = u16::from_le_bytes([hdr[1], hdr[2]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ipc frame"));
    }
    s.read_exact(&mut buf[..len])?;
    Ok((hdr[0], len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn roundtrip_over_socketpair() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        send(&mut a, UiToCore::Line as u8, b"hello \xff\x00 bytes").unwrap();
        send(&mut a, UiToCore::Quit as u8, &[]).unwrap();
        let mut buf = [0u8; MAX_FRAME];
        let (t, n) = recv(&mut b, &mut buf).unwrap();
        assert_eq!((t, &buf[..n]), (1, &b"hello \xff\x00 bytes"[..]));
        let (t, n) = recv(&mut b, &mut buf).unwrap();
        assert_eq!((t, n), (2, 0));
    }

    #[test]
    fn max_frame_ok_and_oversize_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let body = vec![0xAB; MAX_FRAME];
        let t = std::thread::spawn(move || send(&mut a, 1, &body).unwrap());
        let mut buf = [0u8; MAX_FRAME];
        assert_eq!(recv(&mut b, &mut buf).unwrap(), (1, MAX_FRAME));
        t.join().unwrap();
        assert!(send(&mut b, 1, &vec![0; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn hostile_length_is_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&[1, 0xFF, 0xFF]).unwrap();
        let mut buf = [0u8; MAX_FRAME];
        assert_eq!(
            recv(&mut b, &mut buf).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn eof_is_error() {
        let (a, mut b) = UnixStream::pair().unwrap();
        drop(a);
        let mut buf = [0u8; MAX_FRAME];
        assert!(recv(&mut b, &mut buf).is_err());
    }
}
