use std::io::{Write, stdout};
use std::sync::Arc;
use std::thread;

use crate::ffi::transport::TransportHandle;
use crate::proto::cell::{self, Kind};
use crate::proto::frame::Reassembler;
use crate::proto::params::CELL_LEN;

/// Collects exactly `CELL_LEN` bytes from the transport.
fn read_exact_cell(
    transport: &TransportHandle,
    cell: &mut [u8; CELL_LEN],
) -> Result<(), &'static str> {
    let mut filled = 0;
    while filled < CELL_LEN {
        let n = transport.recv(0, &mut cell[filled..]);
        if n <= 0 {
            return Err("transport closed");
        }
        filled += n as usize;
    }
    Ok(())
}

pub fn spawn(transport: Arc<TransportHandle>, username: String) {
    thread::spawn(move || {
        let mut cell = [0u8; CELL_LEN];
        let mut asm = Reassembler::new();
        loop {
            if read_exact_cell(&transport, &mut cell).is_err() {
                crate::shutdown::secure_shutdown();
                return;
            }
            // Authentication/format failure is tampering: fatal.
            let frag = match crate::crypto::secret::with_recv(|c| cell::decode(c, &cell)) {
                Ok(f) => f,
                Err(_) => {
                    crate::shutdown::secure_shutdown();
                    return;
                }
            };
            if frag.kind == Kind::Noise {
                continue;
            }
            match asm.push(frag) {
                Ok(Some((Kind::Chat, msg))) => {
                    let msg = String::from_utf8_lossy(&msg);
                    print!(
                        "\r\x1b[K\x1b[1;30m[\x1b[0m\x1b[1;32mPEER\x1b[0m\x1b[1;30m]\x1b[0m \x1b[32m{}\x1b[0m\n\x1b[1;31m[\x1b[0m\x1b[1;35m{}@lethe\x1b[0m\x1b[1;31m]\x1b[0m\x1b[1;34m~\x1b[0m\x1b[1;31m#\x1b[0m ",
                        msg, username
                    );
                    let _ = stdout().flush();
                }
                Ok(_) => {} // file kinds (§6) not handled yet
                Err(_) => {
                    crate::shutdown::secure_shutdown();
                    return;
                }
            }
        }
    });
}
