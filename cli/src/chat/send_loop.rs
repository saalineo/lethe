use std::io::{Write, stdout};

use crate::chat::router::HostRouter;
use crate::hardening::input::read_line_raw;

pub fn run(router: &HostRouter, username: &str) {
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

        if let Ok(ciphertext) = crate::crypto::secret::seal(line.as_bytes()) {
            router.fan_out(&ciphertext);
        }
    }
}
