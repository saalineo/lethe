use std::time::Duration;

/// Wire-format version. Folded into the PAKE transcript so peers with
/// different cell parameters fail key agreement instead of desyncing.
pub const PROTO_VERSION: u8 = 1;

/// Fixed on-wire size of every cell (ciphertext + tag).
pub const CELL_LEN: usize = 512;
pub const TAG_LEN: usize = 16;
pub const PLAIN_LEN: usize = CELL_LEN - TAG_LEN;
pub const HDR_LEN: usize = 4;
pub const MAX_PAYLOAD: usize = PLAIN_LEN - HDR_LEN;

/// Constant transmit cadence: exactly one cell per tick.
pub const TICK: Duration = Duration::from_millis(100);

/// Upper bound on a reassembled message before the session is aborted.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// Builds a PAKE identity bound to the protocol parameters.
pub fn bound_identity(base: &[u8]) -> Vec<u8> {
    let mut id = base.to_vec();
    id.push(b'|');
    id.push(PROTO_VERSION);
    id.extend_from_slice(&(CELL_LEN as u16).to_le_bytes());
    id.extend_from_slice(&(TICK.as_millis() as u32).to_le_bytes());
    id
}
