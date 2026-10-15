//! Sandboxed terminal UI process (placeholder until the poll loop lands).
use std::os::unix::net::UnixStream;

pub fn run(_ipc: UnixStream, _tty_fd: i32) -> ! {
    // SAFETY: terminates the forked UI child without running destructors.
    unsafe { libc::_exit(0) }
}

/// Installs signal handlers that restore the terminal (filled in with the UI loop).
pub fn install_restore_handlers() {}
