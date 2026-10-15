use super::cell::{FLAG_LAST, Frag, Kind};
use super::params::MAX_PAYLOAD;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::sync::mpsc::SyncSender;
use zeroize::Zeroizing;

/// File-transfer wire version carried in `FILE_BEGIN`.
pub const FILE_VERSION: u8 = 1;

/// `Ctrl` payload: receiver confirms a verified file.
pub const CTRL_ACK: u8 = 1;

/// Process exit codes for file mode.
pub const EXIT_OK: i32 = 0;
pub const EXIT_LOCAL: i32 = 1;
pub const EXIT_MISMATCH: i32 = 2;
pub const EXIT_TRUNCATED: i32 = 3;

/// `FILE_BEGIN`: version only; no name and no size (stdin is a stream).
pub fn begin_frag() -> Frag {
    Frag {
        kind: Kind::FileBegin,
        flags: FLAG_LAST,
        payload: vec![FILE_VERSION],
    }
}

/// `FILE_END`: SHA-256 over all `FILE_DATA` bytes.
pub fn end_frag(digest: [u8; 32]) -> Frag {
    Frag {
        kind: Kind::FileEnd,
        flags: FLAG_LAST,
        payload: digest.to_vec(),
    }
}

pub fn ack_frag() -> Frag {
    Frag {
        kind: Kind::Ctrl,
        flags: FLAG_LAST,
        payload: vec![CTRL_ACK],
    }
}

/// Depth of the queue in file mode: at most ~4 KB of plaintext is buffered,
/// so reading `input` is throttled to the cell tick (backpressure).
pub const FILE_QUEUE_DEPTH: usize = 8;

/// Streams `input` as `FILE_BEGIN`, `FILE_DATA`*, `FILE_END(sha256)`.
pub fn send_stream<R: Read>(mut input: R, queue: &SyncSender<Frag>) -> io::Result<()> {
    let gone = |_| io::Error::new(io::ErrorKind::BrokenPipe, "send queue closed");
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new([0u8; MAX_PAYLOAD]);

    queue.send(begin_frag()).map_err(gone)?;
    loop {
        let n = match input.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        queue
            .send(Frag {
                kind: Kind::FileData,
                flags: 0,
                payload: buf[..n].to_vec(),
            })
            .map_err(gone)?;
    }
    queue.send(end_frag(hasher.finalize().into())).map_err(gone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    #[test]
    fn sender_frames_stream_with_trailing_hash() {
        let data: Vec<u8> = (0..1500u32).map(|i| (i * 7) as u8).collect();
        let (tx, rx) = sync_channel(64);
        send_stream(&data[..], &tx).unwrap();
        drop(tx);
        let frags: Vec<Frag> = rx.iter().collect();

        assert_eq!(frags[0].kind, Kind::FileBegin);
        assert_eq!(frags[0].payload, vec![FILE_VERSION]);
        let last = frags.last().unwrap();
        assert_eq!(last.kind, Kind::FileEnd);
        assert_eq!(last.flags, FLAG_LAST);

        let body: Vec<u8> = frags[1..frags.len() - 1]
            .iter()
            .inspect(|f| assert_eq!(f.kind, Kind::FileData))
            .flat_map(|f| f.payload.iter().copied())
            .collect();
        assert_eq!(body, data);
        assert_eq!(last.payload, Sha256::digest(&data).to_vec());
        assert_eq!(frags.len(), 2 + 4); // 1500 / 492 -> 4 data cells
    }

    #[test]
    fn empty_input_is_begin_then_end() {
        let (tx, rx) = sync_channel(8);
        send_stream(&b""[..], &tx).unwrap();
        drop(tx);
        let kinds: Vec<Kind> = rx.iter().map(|f| f.kind).collect();
        assert_eq!(kinds, [Kind::FileBegin, Kind::FileEnd]);
    }
}
