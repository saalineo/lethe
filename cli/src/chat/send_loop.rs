use std::io::{Write, stdout};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::thread;
use std::time::Instant;

use crate::ffi::transport::TransportHandle;
use crate::hardening::input::read_line_raw;
use crate::proto::cell::{self, Frag, Kind};
use crate::proto::frame;
use crate::proto::params::{MAX_MESSAGE, TICK};

/// Pending fragments waiting for a transmit slot (backpressure on the UI).
pub const QUEUE_DEPTH: usize = 1024;

/// Spawns the constant-rate scheduler: exactly one cell per `TICK`, real
/// fragment if queued, otherwise a noise cell built through the same path.
pub fn spawn_scheduler(queue: Receiver<Frag>, transport: Arc<TransportHandle>) {
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

            let cell = match crate::crypto::secret::with_send(|c| cell::encode(c, &frag)) {
                Ok(c) => c,
                Err(_) => {
                    crate::shutdown::secure_shutdown();
                    return;
                }
            };
            if transport.send(&cell) < 0 {
                crate::shutdown::secure_shutdown();
                return;
            }
        }
    });
}

/// UI side: reads whole lines and queues their fragments; never touches the wire.
pub fn run(queue: SyncSender<Frag>, username: &str) {
    loop {
        print!(
            "\x1b[1;31m[\x1b[0m\x1b[1;35m{}@lethe\x1b[0m\x1b[1;31m]\x1b[0m\x1b[1;34m~\x1b[0m\x1b[1;31m#\x1b[0m ",
            username
        );
        if stdout().flush().is_err() {
            break;
        }
        let line = read_line_raw();

        if line.eq_ignore_ascii_case("exit") || line.eq_ignore_ascii_case("quit") {
            crate::shutdown::secure_shutdown();
            break;
        }

        if line.is_empty() {
            continue;
        }

        if line.len() > MAX_MESSAGE {
            eprintln!("\r\n[!] message too long (max {} bytes)", MAX_MESSAGE);
            continue;
        }

        for f in frame::fragment(Kind::Chat, line.as_bytes()) {
            if queue.send(f).is_err() {
                return;
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ratchet::{Chain, SessionKeys};
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
        let _lock = crate::crypto::secret::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let key = [9u8; 32];
        crate::crypto::secret::set_session(SessionKeys {
            send: Chain::new(key),
            recv: Chain::new(key),
        });

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
        spawn_scheduler(rx, Arc::clone(&client));

        let mut chain = Chain::new(key);
        let mut asm = frame::Reassembler::new();
        let mut got = None;
        let mut kinds = Vec::new();
        let mut times = Vec::new();
        for _ in 0..6 {
            let mut buf = [0u8; CELL_LEN];
            assert_eq!(server.recv(0, &mut buf), CELL_LEN as i32);
            times.push(Instant::now());
            let f = cell::decode(&mut chain, &buf).unwrap();
            kinds.push(f.kind);
            if f.kind != Kind::Noise {
                if let Some(m) = asm.push(f).unwrap() {
                    got = Some(m);
                }
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
        crate::crypto::secret::wipe_session();
    }
}
