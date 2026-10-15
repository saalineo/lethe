use std::io::{stdout, Write};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use crate::crypto::ratchet::RatchetState;

const RECV_BUF_SIZE: usize = 32 * 1024;

pub fn spawn(
    router_arc: Arc<RwLock<crate::ffi::transport::TransportHandle>>,
    recv_ratchet: Arc<std::sync::Mutex<RatchetState>>,
    username: String,
) {
    thread::spawn(move || {
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        loop {
            if let Ok(t) = router_arc.read()
                && let n = t.recv(0, &mut buf)
                && n > 0
                && let Ok(mut ratchet) = recv_ratchet.lock()
                && let Ok(plaintext) = ratchet.decrypt(&buf[..n as usize])
            {
                let msg = String::from_utf8_lossy(&plaintext);

                print!(
                    "\r\x1b[K\x1b[1;30m[\x1b[0m\x1b[1;32mPEER\x1b[0m\x1b[1;30m]\x1b[0m \x1b[32m{}\x1b[0m\n\x1b[1;31m[\x1b[0m\x1b[1;35m{}@lethe\x1b[0m\x1b[1;31m]\x1b[0m\x1b[1;34m~\x1b[0m\x1b[1;31m#\x1b[0m ",
                    msg, username
                );
                let _ = stdout().flush();
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
}
