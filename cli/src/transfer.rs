//! Non-interactive file modes: `SendStdin` and `RecvStdout`.
//!
//! Both functions return the process exit code; the caller shuts down.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::mpsc::{channel, sync_channel};
use std::thread;
use std::time::Duration;

use crate::chat::recv_loop::{self, End, Flow};
use crate::chat::send_loop::spawn_scheduler;
use crate::ffi::transport::TransportHandle;
use crate::proto::cell::{CellKeys, Kind};
use crate::proto::file::{
    self, CTRL_ACK, Done, EXIT_LOCAL, EXIT_MISMATCH, EXIT_OK, EXIT_TRUNCATED, FILE_QUEUE_DEPTH,
    RecvState,
};

/// How long the sender waits for the receiver's `Ctrl(ACK)` after `FILE_END`.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Streams `input` to the peer and waits for the receiver's confirmation.
///
/// Noise keeps flowing at the normal cadence while waiting.
pub fn run_send(
    transport: Arc<TransportHandle>,
    keys: Arc<dyn CellKeys>,
    input: impl Read,
    ack_timeout: Duration,
    fail_code: Option<i32>,
) -> i32 {
    let (tx, rx) = sync_channel(FILE_QUEUE_DEPTH);
    let _sched = spawn_scheduler(rx, Arc::clone(&transport), Arc::clone(&keys), fail_code);

    let (ack_tx, ack_rx) = channel::<()>();
    let rx_transport = Arc::clone(&transport);
    let rx_keys = Arc::clone(&keys);
    thread::spawn(move || {
        recv_loop::run(&rx_transport, &*rx_keys, |f| {
            if f.kind == Kind::Ctrl && f.payload.first() == Some(&CTRL_ACK) {
                let _ = ack_tx.send(());
                return Ok(Flow::Stop);
            }
            Ok(Flow::Continue)
        })
    });

    if file::send_stream(input, &tx).is_err() {
        return EXIT_LOCAL;
    }
    // `tx` stays alive so noise continues until the ACK arrives. A closed
    // transport drops `ack_tx` and wakes us immediately.
    match ack_rx.recv_timeout(ack_timeout) {
        Ok(()) => EXIT_OK,
        Err(_) => EXIT_TRUNCATED,
    }
}

/// Writes the peer's stream to `out`, verifies the trailer hash and acknowledges.
pub fn run_recv(
    transport: Arc<TransportHandle>,
    keys: Arc<dyn CellKeys>,
    mut out: impl Write,
    fail_code: Option<i32>,
) -> i32 {
    let (tx, rx) = sync_channel(FILE_QUEUE_DEPTH);
    let sched = spawn_scheduler(rx, Arc::clone(&transport), Arc::clone(&keys), fail_code);

    let mut st = RecvState::new();
    let mut verdict = EXIT_LOCAL;
    let end = recv_loop::run(&transport, &*keys, |f| match st.on_frag(&mut out, f) {
        Ok(Done::No) => Ok(Flow::Continue),
        Ok(Done::Ok) => Ok(Flow::Stop),
        Err(e) => {
            verdict = e.exit_code();
            Err(())
        }
    });

    match end {
        End::Stopped => {
            // Queue the ACK, then let the scheduler drain it before we return.
            let _ = tx.send(file::ack_frag());
            drop(tx);
            let _ = sched.join();
            EXIT_OK
        }
        End::Closed => EXIT_TRUNCATED,
        End::Tampered => EXIT_MISMATCH,
        End::Failed => verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::cell::LocalKeys;

    fn lib() -> Option<&'static str> {
        ["target/debug/liblethe.so", "../target/debug/liblethe.so"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
    }

    fn pair(lib_path: &'static str) -> (Arc<TransportHandle>, Arc<TransportHandle>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("127.0.0.1:{}", l.local_addr().unwrap().port());
        drop(l);
        let a = addr.clone();
        let s = thread::spawn(move || TransportHandle::load(lib_path, true, &a).unwrap());
        thread::sleep(Duration::from_millis(100));
        let c = TransportHandle::load(lib_path, false, &addr).unwrap();
        (Arc::new(s.join().unwrap()), Arc::new(c))
    }

    struct Shared(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn end_to_end_transfer_verifies_and_acks() {
        let Some(lib_path) = lib() else { return };
        let (server, client) = pair(lib_path);
        let (k_a, k_b) = ([1u8; 32], [2u8; 32]); // c2s, s2c
        let data: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();

        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink2 = Arc::clone(&sink);
        let recv = thread::spawn(move || {
            run_recv(server, Arc::new(LocalKeys::new(k_b, k_a)), Shared(sink2), None)
        });

        let code = run_send(
            client,
            Arc::new(LocalKeys::new(k_a, k_b)),
            &data[..],
            Duration::from_secs(10),
            None,
        );
        assert_eq!(code, EXIT_OK);
        assert_eq!(recv.join().unwrap(), EXIT_OK);
        assert_eq!(*sink.lock().unwrap(), data);
    }

    /// ~10 s: 50 KB at one 492-byte cell per 100 ms. Run with `--ignored`.
    #[test]
    #[ignore]
    fn large_transfer_is_bit_exact() {
        let Some(lib_path) = lib() else { return };
        let (server, client) = pair(lib_path);
        let (k_a, k_b) = ([5u8; 32], [6u8; 32]);
        let data: Vec<u8> = (0..50_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = Arc::clone(&sink);
        let recv = thread::spawn(move || {
            run_recv(server, Arc::new(LocalKeys::new(k_b, k_a)), Shared(s2), None)
        });
        let code = run_send(
            client,
            Arc::new(LocalKeys::new(k_a, k_b)),
            &data[..],
            Duration::from_secs(10),
            None,
        );
        assert_eq!((code, recv.join().unwrap()), (EXIT_OK, EXIT_OK));
        assert_eq!(*sink.lock().unwrap(), data);
    }

    #[test]
    fn truncated_stream_reports_exit_3() {
        let Some(lib_path) = lib() else { return };
        let (server, client) = pair(lib_path);
        let (k_a, k_b) = ([3u8; 32], [4u8; 32]);

        // Peer sends FILE_BEGIN + one data cell, then vanishes.
        let keys = Arc::new(LocalKeys::new(k_a, k_b));
        let (tx, rx) = sync_channel(8);
        let sched = spawn_scheduler(rx, Arc::clone(&client), keys, None);
        tx.send(file::begin_frag()).unwrap();
        tx.send(crate::proto::cell::Frag {
            kind: Kind::FileData,
            flags: 0,
            payload: vec![7; 10],
        })
        .unwrap();
        drop(tx);
        sched.join().unwrap();
        // closing the client side: drop all handles to it
        client.syms.stop(client.node_handle);

        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let code = run_recv(server, Arc::new(LocalKeys::new(k_b, k_a)), Shared(sink), None);
        assert_eq!(code, EXIT_TRUNCATED);
    }

    #[test]
    fn mismatched_keys_are_fatal_not_success() {
        let Some(lib_path) = lib() else { return };
        let (server, client) = pair(lib_path);
        let recv = thread::spawn(move || {
            run_recv(
                server,
                Arc::new(LocalKeys::new([9u8; 32], [9u8; 32])),
                Shared(Default::default()),
                None,
            )
        });
        let code = run_send(
            client,
            Arc::new(LocalKeys::new([8u8; 32], [8u8; 32])),
            &b"data"[..],
            Duration::from_secs(5),
            None,
        );
        assert_ne!(code, EXIT_OK);
        assert_eq!(recv.join().unwrap(), EXIT_MISMATCH);
    }
}
