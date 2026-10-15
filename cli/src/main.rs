mod chat;
mod crypto;
mod ffi;
mod hardening;
mod shutdown;
mod username;

use chat::router::HostRouter;
use crypto::ratchet::RatchetState;
use ffi::transport::TransportHandle;
use hardening::{anti_debug, dump, memory, namespace, seccomp, signals, watchdog};
use obfstr::obfstr;
use sha2::Digest;
use std::env;
use std::panic;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    panic::set_hook(Box::new(|info| {
        eprintln!(
            "\n[CRITICAL] Panic detected at {:?}!",
            info.location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown".to_string())
        );
        if let Some(s) = info.payload().downcast_ref::<&str>() {
            eprintln!("[!] Message: {}", s);
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            eprintln!("[!] Message: {}", s);
        }
        shutdown::secure_shutdown();
    }));

    anti_debug::block_debugger();
    if let Err(e) = dump::disable_core_dumps() {
        eprintln!("[!] Failed to disable core dumps: {}", e);
    }

    watchdog::secure_launch(|| {
        if let Err(e) = namespace::isolate_environment() {
            eprintln!("\x1b[1;31m[!] Access Denied: {}\x1b[0m", e);
            eprintln!("\x1b[1;33m[i] Please apply capabilities instead of running as root:\x1b[0m");
            eprintln!("    sudo setcap cap_ipc_lock,cap_sys_admin+ep target/release/sirfz");
            std::process::exit(1);
        }

        if let Err(e) = memory::lock_memory() {
            eprintln!("\x1b[1;31m[!] Memory Lock Failed: {}\x1b[0m", e);
            eprintln!("\x1b[1;33m[i] Missing cap_ipc_lock. Please apply capabilities:\x1b[0m");
            eprintln!("    sudo setcap cap_ipc_lock,cap_sys_admin+ep target/release/sirfz");
            std::process::exit(1);
        }
        if let Err(e) = seccomp::enforce_syscall_boundaries() {
            eprintln!("\x1b[1;31m[!] Seccomp failed: {}\x1b[0m", e);
            std::process::exit(1);
        }
        if let Err(e) = signals::install_signal_handlers() {
            eprintln!("\x1b[1;31m[!] Signal handlers failed: {}\x1b[0m", e);
            std::process::exit(1);
        }

        let args: Vec<String> = env::args().collect();
        let is_server = args.iter().any(|a| a == "--server");
        let addr = args
            .iter()
            .position(|a| a == "--addr")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("0.0.0.0:9000");

        let lib_path = args
            .iter()
            .position(|a| a == "--lib")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or_else(|| {
                if std::path::Path::new("./libsirfz.so").exists() {
                    "./libsirfz.so"
                } else if std::path::Path::new("./libtransport.so").exists() {
                    "./libtransport.so"
                } else {
                    "../libtransport/target/release/libsirfz.so"
                }
            });

        eprintln!(
            "\x1b[1;30m[+]\x1b[0m \x1b[32m{}\x1b[0m",
            obfstr!("SECURE ENVIRONMENT ACTIVE")
        );
        eprintln!(
            "\x1b[1;30m[+]\x1b[0m \x1b[32mTransport: {} | Mode: {}\x1b[0m\n",
            addr,
            if is_server { "SERVER" } else { "CLIENT" }
        );

        let mut auth_key = [0u8; 32];
        loop {
            eprint!("\x1b[1;31m>\x1b[0m \x1b[1;33mEnter Session PIN:\x1b[0m ");
            let mut pin = hardening::input::read_pin_stealth();
            eprintln!(); // newline after stealth reading

            let trimmed = pin.trim();
            if trimmed.is_empty() {
                eprintln!("\x1b[1;31m[!] PIN cannot be empty. Please try again.\x1b[0m");
                continue;
            }

            let mut hasher = sha2::Sha256::new();
            hasher.update(trimmed.as_bytes());
            let result = hasher.finalize();
            auth_key.copy_from_slice(&result);

            pin.zeroize();
            break;
        }

        eprintln!("\x1b[1;30m[+]\x1b[0m Session Secured.");

        let my_username = username::generate_username();
        eprintln!("\n\x1b[1;30m[+]\x1b[0m \x1b[32mAssigned Alias: {}\x1b[0m\n", my_username);

        let transport = TransportHandle::load(lib_path, is_server, addr, &auth_key)
            .map_err(|e| format!("transport init failed: {}", e))?;

        let root_key = [0x42u8; 32];
        let send_ratchet = RatchetState::new(root_key);
        let recv_ratchet = Arc::new(Mutex::new(RatchetState::new(root_key)));

        let router = HostRouter::new(transport);
        chat::terminal::run(router, send_ratchet, recv_ratchet, my_username);

        Ok(())
    });

    Ok(())
}
