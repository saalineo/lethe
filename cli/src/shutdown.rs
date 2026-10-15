use crate::hardening::memory;
use std::process;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::Once;

static SHUTDOWN_ONCE: Once = Once::new();

pub fn secure_shutdown() {
    SHUTDOWN_ONCE.call_once(|| {
        eprintln!("\n[!] Secure shutdown initiated. Wiping memory...");

        compiler_fence(Ordering::SeqCst);
        memory::unlock_memory();

        process::exit(0);
    });
}
