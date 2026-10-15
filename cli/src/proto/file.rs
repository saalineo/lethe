use super::cell::{FLAG_LAST, Frag, Kind};
use super::params::MAX_PAYLOAD;
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Idle,
    Receiving,
    Finished,
}

pub struct RecvState {
    phase: Phase,
    hasher: Sha256,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Done {
    No,
    Ok,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileError {
    /// Output could not be written (e.g. downstream pipe closed).
    Output,
    /// Trailer hash differs from the received bytes.
    HashMismatch,
    /// Out-of-order or foreign cell kind.
    Unexpected,
}

impl FileError {
    pub fn exit_code(self) -> i32 {
        match self {
            FileError::Output => EXIT_LOCAL,
            FileError::HashMismatch | FileError::Unexpected => EXIT_MISMATCH,
        }
    }
}

impl RecvState {
    pub fn new() -> Self {
        Self {
            phase: Phase::Idle,
            hasher: Sha256::new(),
        }
    }

    /// Consumes one file cell; data is written through immediately, nothing is kept.
    pub fn on_frag(&mut self, out: &mut impl Write, f: Frag) -> Result<Done, FileError> {
        match (f.kind, self.phase) {
            (Kind::FileBegin, Phase::Idle) => {
                if f.payload.first() != Some(&FILE_VERSION) {
                    return Err(FileError::Unexpected);
                }
                self.phase = Phase::Receiving;
                Ok(Done::No)
            }
            (Kind::FileData, Phase::Receiving) => {
                self.hasher.update(&f.payload);
                out.write_all(&f.payload).map_err(|_| FileError::Output)?;
                out.flush().map_err(|_| FileError::Output)?;
                Ok(Done::No)
            }
            (Kind::FileEnd, Phase::Receiving) => {
                self.phase = Phase::Finished;
                if self.hasher.clone().finalize().as_slice() == &f.payload[..] {
                    Ok(Done::Ok)
                } else {
                    Err(FileError::HashMismatch)
                }
            }
            _ => Err(FileError::Unexpected),
        }
    }
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

    fn frames(data: &[u8]) -> Vec<Frag> {
        let (tx, rx) = sync_channel(64);
        send_stream(data, &tx).unwrap();
        drop(tx);
        rx.iter().collect()
    }

    #[test]
    fn receiver_writes_through_and_verifies() {
        let data = vec![0x5Au8; 3000];
        let mut st = RecvState::new();
        let mut out = Vec::new();
        let mut res = Done::No;
        for f in frames(&data) {
            res = st.on_frag(&mut out, f).unwrap();
        }
        assert_eq!(res, Done::Ok);
        assert_eq!(out, data);
    }

    #[test]
    fn receiver_detects_mismatch_and_order_errors() {
        let mut fr = frames(b"hello");
        fr.last_mut().unwrap().payload[0] ^= 1;
        let mut st = RecvState::new();
        let mut out = Vec::new();
        let mut err = None;
        for f in fr {
            if let Err(e) = st.on_frag(&mut out, f) {
                err = Some(e);
            }
        }
        assert_eq!(err, Some(FileError::HashMismatch));
        assert_eq!(err.unwrap().exit_code(), EXIT_MISMATCH);

        // data before begin
        let mut st = RecvState::new();
        let f = Frag { kind: Kind::FileData, flags: 0, payload: vec![1] };
        assert_eq!(st.on_frag(&mut out, f), Err(FileError::Unexpected));
        // chat during a transfer
        let mut st = RecvState::new();
        st.on_frag(&mut out, begin_frag()).unwrap();
        let f = Frag { kind: Kind::Chat, flags: FLAG_LAST, payload: vec![] };
        assert_eq!(st.on_frag(&mut out, f), Err(FileError::Unexpected));
    }

    #[test]
    fn closed_output_is_local_error() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut st = RecvState::new();
        st.on_frag(&mut Broken, begin_frag()).unwrap();
        let f = Frag { kind: Kind::FileData, flags: 0, payload: vec![1] };
        let e = st.on_frag(&mut Broken, f).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_LOCAL);
    }
}
