use super::cell::{FLAG_LAST, Frag, Kind};

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
