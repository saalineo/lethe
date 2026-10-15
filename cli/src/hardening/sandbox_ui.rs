//! Forks and confines the terminal UI process.
//!
//! The UI sees plaintext and the terminal but never keys or the network:
//! empty capabilities, `NO_NEW_PRIVS`, private net/IPC/UTS namespaces, only
//! three descriptors left, and a strict seccomp profile.

use super::seccomp::{self, Profile};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Removes every capability: bounding set, ambient set, and the
/// effective/permitted/inheritable sets of this thread.
pub fn drop_all_caps() -> io::Result<()> {
    // SAFETY: plain prctl/capset calls with valid, fully initialised arguments.
    unsafe {
        for cap in 0..64 {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) != 0 {
                match io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINVAL) => break, // past the last valid capability
                    Some(libc::EPERM) => break,  // no CAP_SETPCAP: nothing left to drop
                    _ => return Err(io::Error::last_os_error()),
                }
            }
        }
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

        let hdr = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
        if libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Closes every descriptor except those in `keep` (enumerated via `/proc/self/fd`).
pub fn close_all_fds_except(keep: &[i32]) -> io::Result<()> {
    let mut fds = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        if let Some(fd) = entry?.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) {
            fds.push(fd);
        }
    }
    for fd in fds {
        if !keep.contains(&fd) {
            // SAFETY: closing descriptors we do not use; EBADF (the dir fd) is harmless.
            unsafe { libc::close(fd) };
        }
    }
    Ok(())
}

/// Points 0/1/2 at `/dev/null` so the UI cannot own the process stdio.
pub fn redirect_stdio_to_devnull() -> io::Result<()> {
    // SAFETY: open/dup2/close on descriptors owned by this process.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if null < 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in 0..3 {
            if libc::dup2(null, fd) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if null > 2 {
            libc::close(null);
        }
    }
    Ok(())
}

/// Applies the full UI confinement to the calling (forked) process.
pub fn confine_self(ipc_fd: i32, tty_fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: process-wide hardening calls with constant arguments.
    unsafe {
        // The UI sees plaintext too: keep it out of swap and un-dumpable.
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // No network / SysV IPC / hostname even if seccomp were bypassed.
        if libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS) != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    crate::ui::install_restore_handlers();
    close_all_fds_except(&[0, 1, 2, ipc_fd, tty_fd])?;
    redirect_stdio_to_devnull()?;
    drop_all_caps()?;
    // SAFETY: NO_NEW_PRIVS is monotonic and takes constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    seccomp::enforce(Profile::Ui { ipc_fd, tty_fd })?;
    Ok(())
}

/// Forks the UI. Returns the core's end of the socketpair and the UI pid.
///
/// `tty_fd` must stay open in the child; the caller drops its own copy after
/// this returns.
pub fn spawn_ui(tty_fd: i32) -> io::Result<(UnixStream, libc::pid_t)> {
    let (core_end, ui_end) = UnixStream::pair()?;

    // SAFETY: the child only runs this function's straight-line code and
    // `ui::run`, then `_exit`s; it never returns into the parent's stack.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            drop(core_end);
            let ipc_fd = ui_end.as_raw_fd();
            if confine_self(ipc_fd, tty_fd).is_err() {
                // Fail closed: the core sees EOF and shuts down.
                unsafe { libc::_exit(1) };
            }
            crate::ui::run(ui_end, tty_fd)
        }
        pid => Ok((core_end, pid)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_child(body: fn()) -> i32 {
        // SAFETY: the child runs `body` and exits without unwinding.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                body();
                libc::_exit(0);
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            st
        }
    }

    fn status_field(name: &str) -> String {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap()
            .to_string()
    }

    #[test]
    fn caps_are_emptied() {
        let st = in_child(|| {
            if drop_all_caps().is_err() {
                unsafe { libc::_exit(10) };
            }
            let eff = status_field("CapEff:");
            let prm = status_field("CapPrm:");
            let ok = eff.trim_end().ends_with("0000000000000000")
                && prm.trim_end().ends_with("0000000000000000");
            unsafe { libc::_exit(if ok { 0 } else { 11 }) };
        });
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "status {st}");
    }

    #[test]
    fn only_listed_fds_survive() {
        let st = in_child(|| {
            // SAFETY: duplicating stdin to create extra descriptors.
            let (a, b) = unsafe { (libc::dup(0), libc::dup(0)) };
            if close_all_fds_except(&[0, 1, 2, a]).is_err() {
                unsafe { libc::_exit(10) };
            }
            let a_open = unsafe { libc::fcntl(a, libc::F_GETFD) } != -1;
            let b_closed = unsafe { libc::fcntl(b, libc::F_GETFD) } == -1;
            unsafe { libc::_exit(if a_open && b_closed { 0 } else { 11 }) };
        });
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "status {st}");
    }
}
