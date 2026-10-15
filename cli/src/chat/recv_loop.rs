use std::io::{Write, stdout};
use std::sync::Arc;
use std::thread;

const RECV_BUF_SIZE: usize = 32 * 1024;

pub fn spawn(transport: Arc<crate::ffi::transport::TransportHandle>, username: String) {
    thread::spawn(move || {
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        loop {
            // Do not hold any router lock across blocking recv
            let n = transport.recv(0, &mut buf);
            if n < 0 {
                // Peer disconnected: trigger secure shutdown immediately
                crate::shutdown::secure_shutdown();
                break;
            }
            if n > 0
                && let Ok(plaintext) = crate::crypto::secret::open(&buf[..n as usize])
            {
                let msg = String::from_utf8_lossy(&plaintext);

                print!(
                    "\r\x1b[K\x1b[1;30m[\x1b[0m\x1b[1;32mPEER\x1b[0m\x1b[1;30m]\x1b[0m \x1b[32m{}\x1b[0m\n\x1b[1;31m[\x1b[0m\x1b[1;35m{}@lethe\x1b[0m\x1b[1;31m]\x1b[0m\x1b[1;34m~\x1b[0m\x1b[1;31m#\x1b[0m ",
                    msg, username
                );
                let _ = stdout().flush();
            }
        }
    });
}
