mod chat;
mod crypto;
mod ffi;
mod hardening;
mod mode;
mod transfer;
mod proto;
mod shutdown;
mod username;

use chat::router::HostRouter;
use ffi::transport::TransportHandle;
use hardening::{anti_debug, dump, memory, namespace, seccomp, signals, watchdog};
use obfstr::obfstr;
use std::env;
use std::panic;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    panic::set_hook(Box::new(|info| {
        crate::status_ln!(
            "\n[CRITICAL] Panic detected at {:?}!",
            info.location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown".to_string())
        );
        if let Some(s) = info.payload().downcast_ref::<&str>() {
            crate::status_ln!("[!] Message: {}", s);
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            crate::status_ln!("[!] Message: {}", s);
        }
        shutdown::secure_shutdown();
    }));

    anti_debug::block_debugger();
    if let Err(e) = dump::disable_core_dumps() {
        crate::status_ln!("[!] Failed to disable core dumps: {}", e);
    }

    watchdog::secure_launch(|| {
        if let Err(e) = namespace::isolate_environment() {
            crate::status_ln!("\x1b[1;31m[!] Access Denied: {}\x1b[0m", e);
            crate::status_ln!("\x1b[1;33m[i] Please apply capabilities instead of running as root:\x1b[0m");
            crate::status_ln!("    sudo setcap cap_ipc_lock,cap_sys_admin+ep target/release/lethe");
            std::process::exit(1);
        }

        if let Err(e) = memory::lock_memory() {
            crate::status_ln!("\x1b[1;31m[!] Memory Lock Failed: {}\x1b[0m", e);
            crate::status_ln!("\x1b[1;33m[i] Missing cap_ipc_lock. Please apply capabilities:\x1b[0m");
            crate::status_ln!("    sudo setcap cap_ipc_lock,cap_sys_admin+ep target/release/lethe");
            std::process::exit(1);
        }
        if let Err(e) = seccomp::enforce_syscall_boundaries() {
            crate::status_ln!("\x1b[1;31m[!] Seccomp failed: {}\x1b[0m", e);
            std::process::exit(1);
        }
        if let Err(e) = signals::install_signal_handlers() {
            crate::status_ln!("\x1b[1;31m[!] Signal handlers failed: {}\x1b[0m", e);
            std::process::exit(1);
        }

        let args: Vec<String> = env::args().collect();
        let is_server = args.iter().any(|a| a == "--server");

        let mode = mode::detect(&args);

        let explicit_addr = args
            .iter()
            .position(|a| a == "--addr")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str());

        let addr = if let Some(a) = explicit_addr {
            a.to_string()
        } else if mode == mode::Mode::Chat {
            read_address_from_tty(is_server)
        } else if is_server {
            "0.0.0.0:9000".to_string()
        } else {
            "127.0.0.1:9000".to_string()
        };

        let explicit_lib = args
            .iter()
            .position(|a| a == "--lib")
            .and_then(|i| args.get(i + 1));

        let lib_path = if let Some(p) = explicit_lib {
            // Explicit --lib: resolve with canonicalize
            std::fs::canonicalize(p)
                .map_err(|e| format!("failed to canonicalize explicit --lib '{}': {}", p, e))?
        } else {
            // Refuse relative paths unless --lib is explicit. Look only in exe directory.
            let exe_dir_lib = env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("liblethe.so")));

            if let Some(ref p) = exe_dir_lib
                && p.exists()
            {
                std::fs::canonicalize(p)
                    .map_err(|e| format!("failed to canonicalize library path: {}", e))?
            } else {
                return Err(
                    "no explicit --lib provided; relative paths refused. Please pass --lib <path>"
                        .into(),
                );
            }
        };

        crate::status_ln!(
            "\x1b[1;30m[+]\x1b[0m \x1b[32m{}\x1b[0m",
            obfstr!("SECURE ENVIRONMENT ACTIVE")
        );
        crate::status_ln!(
            "\x1b[1;30m[+]\x1b[0m \x1b[32mTransport: {} | Mode: {}\x1b[0m\n",
            addr,
            if is_server { "SERVER" } else { "CLIENT" }
        );

        let tty = hardening::secure_tty::Tty::open()
            .map_err(|e| format!("no controlling terminal: {e}"))?;

        let passphrase = loop {
            let s = hardening::secure_tty::read_secret(
                &tty,
                "\x1b[1;31m>\x1b[0m \x1b[1;33mEnter Session Passphrase:\x1b[0m ",
            )?;
            if !s.as_bytes().is_empty() {
                break s;
            }
            tty.write_all(b"\x1b[1;31m[!] Passphrase cannot be empty. Please try again.\x1b[0m\n");
        };
        let pw = crypto::session::stretch(passphrase.as_bytes());
        drop(passphrase); // zeroized immediately

        crate::status_ln!("\x1b[1;30m[+]\x1b[0m Passphrase stretched (Argon2id).");

        let transport = TransportHandle::load(&lib_path.to_string_lossy(), is_server, &addr)
            .map_err(|e| format!("transport init failed: {}", e))?;

        let role = crypto::session::Role::from_is_server(is_server);
        let session_keys = {
            let mut io = transport.io();
            crypto::session::agree(&mut io, role, &pw)
                .map_err(|e| format!("key agreement failed: {}", e))?
        };

        crate::status_ln!("\x1b[1;30m[+]\x1b[0m Session Secured (SPAKE2 + Key Confirmation).");

        crypto::secret::set_session(session_keys);
        drop(pw);

        match mode {
            mode::Mode::Chat => {
                let router = HostRouter::new(transport);
                chat::terminal::run(router);
            }
            mode::Mode::SendStdin => {
                let code = transfer::run_send(
                    std::sync::Arc::new(transport),
                    std::sync::Arc::new(crypto::secret::GlobalSession),
                    std::io::stdin().lock(),
                    transfer::ACK_TIMEOUT,
                    Some(proto::file::EXIT_TRUNCATED),
                );
                finish_transfer("sent", code);
            }
            mode::Mode::RecvStdout => {
                let code = transfer::run_recv(
                    std::sync::Arc::new(transport),
                    std::sync::Arc::new(crypto::secret::GlobalSession),
                    std::io::stdout().lock(),
                    Some(proto::file::EXIT_TRUNCATED),
                );
                finish_transfer("received", code);
            }
        }

        Ok(())
    });

    Ok(())
}

/// Reports the verdict on the tty (never stdout) and exits with its code.
fn finish_transfer(verb: &str, code: i32) -> ! {
    match code {
        proto::file::EXIT_OK => crate::status_ln!("\x1b[1;32m[+] file {verb}, hash verified\x1b[0m"),
        proto::file::EXIT_MISMATCH => {
            crate::status_ln!("\x1b[1;31m[!] integrity failure (hash mismatch / bad frame)\x1b[0m")
        }
        proto::file::EXIT_TRUNCATED => {
            crate::status_ln!("\x1b[1;31m[!] connection closed before transfer completed\x1b[0m")
        }
        _ => crate::status_ln!("\x1b[1;31m[!] local I/O error\x1b[0m"),
    }
    shutdown::secure_shutdown_with(code);
    std::process::exit(code)
}

fn read_address_from_tty(is_server: bool) -> String {
    let default_addr = if is_server {
        "0.0.0.0:9000"
    } else {
        "127.0.0.1:9000"
    };
    let prompt = if is_server {
        "\x1b[1;31m>\x1b[0m \x1b[1;33mEnter Listen Address [0.0.0.0:9000]:\x1b[0m "
    } else {
        "\x1b[1;31m>\x1b[0m \x1b[1;33mEnter Peer Address [127.0.0.1:9000]:\x1b[0m "
    };

    if let Ok(mut tty_out) = std::fs::OpenOptions::new().write(true).open("/dev/tty")
        && let Ok(tty_in) = std::fs::File::open("/dev/tty")
    {
        let _ = std::io::Write::write_all(&mut tty_out, prompt.as_bytes());
        let _ = std::io::Write::flush(&mut tty_out);

        let mut reader = std::io::BufReader::new(tty_in);
        let mut line = String::new();
        if std::io::BufRead::read_line(&mut reader, &mut line).is_ok() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    default_addr.to_string()
}
