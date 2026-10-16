use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;
use std::time::Instant;

use crate::ffi::transport::TransportHandle;
use crate::proto::cell::{CellKeys, Frag};
use crate::proto::params::TICK;

/// Pending fragments waiting for a transmit slot (backpressure on the UI).
pub const QUEUE_DEPTH: usize = 1024;

/// Spawns the constant-rate scheduler: exactly one cell per `TICK`, real
/// fragment if queued, otherwise a noise cell built through the same path.
///
/// A failed `send` shuts the process down with `fail_code`; `None` just ends the thread.
pub fn spawn_scheduler(
    queue: Receiver<Frag>,
    transport: Arc<TransportHandle>,
    keys: Arc<dyn CellKeys>,
    fail_code: Option<i32>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut next = Instant::now() + TICK;
        loop {
            let now = Instant::now();
            if next > now {
                thread::sleep(next - now);
            }
            // Delay semantics: a late tick shifts the schedule, never bursts to catch up.
            next = Instant::now().max(next) + TICK;

            let frag = match queue.try_recv() {
                Ok(f) => f,
                Err(TryRecvError::Empty) => Frag::noise(),
                Err(TryRecvError::Disconnected) => break,
            };

            let cell = match keys.seal(&frag) {
                Ok(c) => c,
                Err(_) => {
                    crate::shutdown::secure_shutdown();
                    return;
                }
            };
            if transport.send(&cell) < 0 {
                if let Some(code) = fail_code {
                    crate::shutdown::secure_shutdown_with(code);
                }
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ratchet::Chain;
    use crate::proto::cell::{Kind, LocalKeys};
    use crate::proto::frame;
    use crate::proto::params::CELL_LEN;
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;

    #[test]
    fn scheduler_emits_constant_rate_cells_with_noise_fill() {
        let lib_path = match ["target/debug/liblethe.so", "../target/debug/liblethe.so"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        {
            Some(p) => *p,
            None => return, // shared library not built
        };
        let key = [9u8; 32];

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);
        let a = addr.clone();
        let server = thread::spawn(move || TransportHandle::load(lib_path, true, &a).unwrap());
        thread::sleep(Duration::from_millis(100));
        let client = Arc::new(TransportHandle::load(lib_path, false, &addr).unwrap());
        let server = server.join().unwrap();

        let msg = vec![b'a'; 1000]; // 3 cells
        let (tx, rx) = sync_channel(QUEUE_DEPTH);
        for f in frame::fragment(Kind::Chat, &msg) {
            tx.send(f).unwrap();
        }
        spawn_scheduler(
            rx,
            Arc::clone(&client),
            Arc::new(LocalKeys::new(key, key)),
            None,
        );

        let mut chain = Chain::new(key);
        let mut asm = frame::Reassembler::new();
        let mut got = None;
        let mut kinds = Vec::new();
        let mut times = Vec::new();
        for _ in 0..6 {
            let mut buf = [0u8; CELL_LEN];
            assert_eq!(server.recv(0, &mut buf), CELL_LEN as i32);
            times.push(Instant::now());
            let f = crate::proto::cell::decode(&mut chain, &buf).unwrap();
            kinds.push(f.kind);
            if f.kind != Kind::Noise
                && let Some(m) = asm.push(f).unwrap()
            {
                got = Some(m);
            }
        }
        assert_eq!(got, Some((Kind::Chat, msg)));
        assert_eq!(
            kinds,
            [Kind::Chat, Kind::Chat, Kind::Chat, Kind::Noise, Kind::Noise, Kind::Noise]
        );
        let span = times[5] - times[0];
        assert!(span >= TICK * 5 - Duration::from_millis(30), "too fast: {span:?}");
        assert!(span < TICK * 5 + Duration::from_millis(250), "too slow: {span:?}");

        drop(tx);
    }
}
