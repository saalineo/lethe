use std::io::{Write, stdout};
use std::sync::Arc;
use std::thread;

use crate::ffi::transport::TransportHandle;
use crate::proto::cell::{CellKeys, Frag, Kind};
use crate::proto::frame::Reassembler;
use crate::proto::params::CELL_LEN;

/// What a fragment handler wants the receive loop to do next.
pub enum Flow {
    Continue,
    Stop,
}

/// Why the receive loop ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum End {
    /// Handler asked to stop.
    Stopped,
    /// Transport closed or failed.
    Closed,
    /// Cell failed authentication/format checks.
    Tampered,
    /// Handler reported a fatal error.
    Failed,
}

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

/// Blocking receive loop: reads cells, drops noise, hands everything else to `on_frag`.
pub fn run(
    transport: &TransportHandle,
    keys: &dyn CellKeys,
    mut on_frag: impl FnMut(Frag) -> Result<Flow, ()>,
) -> End {
    let mut cell = [0u8; CELL_LEN];
    loop {
        if read_exact_cell(transport, &mut cell).is_err() {
            return End::Closed;
        }
        let frag = match keys.open(&cell) {
            Ok(f) => f,
            Err(_) => return End::Tampered,
        };
        if frag.kind == Kind::Noise {
            continue;
        }
        match on_frag(frag) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Stop) => return End::Stopped,
            Err(()) => return End::Failed,
        }
    }
}

/// Chat mode: prints reassembled messages; any end of the loop is a shutdown.
pub fn spawn(transport: Arc<TransportHandle>, username: String) {
    thread::spawn(move || {
        let mut asm = Reassembler::new();
        let end = run(&transport, &crate::crypto::secret::GlobalSession, |frag| {
            if frag.kind != Kind::Chat {
                return Ok(Flow::Continue); // file kinds are not part of chat
            }
            if let Some((_, msg)) = asm.push(frag).map_err(|_| ())? {
                let msg = String::from_utf8_lossy(&msg);
                print!(
                    "\r\x1b[K\x1b[1;30m[\x1b[0m\x1b[1;32mPEER\x1b[0m\x1b[1;30m]\x1b[0m \x1b[32m{}\x1b[0m\n\x1b[1;31m[\x1b[0m\x1b[1;35m{}@lethe\x1b[0m\x1b[1;31m]\x1b[0m\x1b[1;34m~\x1b[0m\x1b[1;31m#\x1b[0m ",
                    msg, username
                );
                let _ = stdout().flush();
            }
            Ok(Flow::Continue)
        });
        match end {
            End::Closed | End::Stopped => crate::shutdown::secure_shutdown(),
            End::Tampered | End::Failed => crate::shutdown::secure_shutdown_with(2),
        }
    });
}
