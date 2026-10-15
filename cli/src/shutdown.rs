use crate::crypto::secret::SESSION;
use crate::hardening::memory;
use std::process;
use std::sync::Once;
use std::sync::atomic::{Ordering, compiler_fence};

static SHUTDOWN_ONCE: Once = Once::new();

pub fn secure_shutdown() {
    SHUTDOWN_ONCE.call_once(|| {
        eprintln!(
            "\n[!] Secure shutdown initiated. Zeroizing session keys and unlocking memory..."
        );

        if let Ok(mut g) = SESSION.lock() {
            g.take(); // ZeroizeOnDrop runs here
        }
        compiler_fence(Ordering::SeqCst);
        memory::unlock_memory();

        process::exit(0);
    });
}
