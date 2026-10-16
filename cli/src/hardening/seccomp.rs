use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

const TCGETS2: u64 = 0x802c_542a;
const TCSETS2: u64 = 0x402c_542b;
const TCSETSW2: u64 = 0x402c_542c;
const TCSETSF2: u64 = 0x402c_542d;

/// Which sandbox profile to load.
pub enum Profile {
    /// The network/crypto core.
    Core,
    /// The terminal UI: no files, sockets, threads or exec; I/O on two fds only.
    Ui { ipc_fd: i32, tty_fd: i32 },
}

pub fn enforce(profile: Profile) -> Result<(), Box<dyn std::error::Error>> {
    match profile {
        Profile::Core => enforce_syscall_boundaries(),
        Profile::Ui { ipc_fd, tty_fd } => {
            let ctx = ui_profile(ipc_fd, tty_fd)?;
            ctx.load()?;
            Ok(())
        }
    }
}

fn ui_profile(ipc_fd: i32, tty_fd: i32) -> Result<ScmpFilterContext, Box<dyn std::error::Error>> {
    let mut c = ScmpFilterContext::new_filter(ScmpAction::KillProcess)?;

    for name in [
        "poll", "ppoll", "exit", "exit_group", "brk", "munmap", "mremap", "futex",
        "rt_sigreturn", "rt_sigprocmask", "clock_gettime", "getrandom", "mmap", "madvise",
        "restart_syscall",
    ] {
        c.add_rule(ScmpAction::Allow, ScmpSyscall::from_name(name)?)?;
    }

    // Allocator growth may need mprotect, but never executable mappings.
    c.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("mprotect")?,
        &[ScmpArgCompare::new(
            2,
            ScmpCompareOp::MaskedEqual(libc::PROT_EXEC as u64),
            0,
        )],
    )?;

    // read/write only on the two descriptors the UI owns.
    for fd in [ipc_fd, tty_fd] {
        for name in ["read", "write"] {
            c.add_rule_conditional(
                ScmpAction::Allow,
                ScmpSyscall::from_name(name)?,
                &[ScmpArgCompare::new(0, ScmpCompareOp::Equal, fd as u64)],
            )?;
        }
    }

    // std's UnixStream read/write use recv/send (recvfrom/sendto): IPC fd only.
    for name in ["recvfrom", "sendto"] {
        c.add_rule_conditional(
            ScmpAction::Allow,
            ScmpSyscall::from_name(name)?,
            &[ScmpArgCompare::new(0, ScmpCompareOp::Equal, ipc_fd as u64)],
        )?;
    }

    // termios and window size only.
    for req in [
        libc::TCGETS as u64,
        libc::TCSETS as u64,
        libc::TCSETSW as u64,
        libc::TCSETSF as u64,
        libc::TIOCGWINSZ as u64,
        // newer glibc drives termios through the termios2 ioctls
        TCGETS2,
        TCSETS2,
        TCSETSW2,
        TCSETSF2,
    ] {
        c.add_rule_conditional(
            ScmpAction::Allow,
            ScmpSyscall::from_name("ioctl")?,
            &[ScmpArgCompare::new(1, ScmpCompareOp::Equal, req)],
        )?;
    }
    Ok(c)
}

pub fn enforce_syscall_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let mut isolation_context = ScmpFilterContext::new_filter(ScmpAction::Trap)?;

    const PERMITTED_SYSTEM_CALLS: &[i32] = &[
        libc::SYS_read as i32,
        libc::SYS_write as i32,
        libc::SYS_writev as i32,
        libc::SYS_open as i32,
        libc::SYS_openat as i32,
        libc::SYS_close as i32,
        libc::SYS_exit_group as i32,
        libc::SYS_exit as i32,
        libc::SYS_brk as i32,
        libc::SYS_mmap as i32,
        libc::SYS_munmap as i32,
        libc::SYS_mremap as i32,
        libc::SYS_mprotect as i32,
        libc::SYS_mlockall as i32,
        libc::SYS_munlockall as i32,
        libc::SYS_madvise as i32,
        libc::SYS_rseq as i32,
        libc::SYS_fstat as i32,
        libc::SYS_newfstatat as i32,
        libc::SYS_statx as i32,
        libc::SYS_lseek as i32,
        libc::SYS_ioctl as i32,
        libc::SYS_fcntl as i32,
        libc::SYS_clone as i32,
        libc::SYS_clone3 as i32,
        libc::SYS_set_robust_list as i32,
        libc::SYS_futex as i32,
        libc::SYS_set_tid_address as i32,
        libc::SYS_tgkill as i32,
        libc::SYS_gettid as i32,
        libc::SYS_nanosleep as i32,
        libc::SYS_clock_nanosleep as i32,
        libc::SYS_rt_sigreturn as i32,
        libc::SYS_rt_sigaction as i32,
        libc::SYS_sigaltstack as i32,
        libc::SYS_rt_sigprocmask as i32,
        libc::SYS_rt_sigsuspend as i32,
        libc::SYS_getrandom as i32,
        libc::SYS_prlimit64 as i32,
        libc::SYS_getuid as i32,
        libc::SYS_getgid as i32,
        libc::SYS_geteuid as i32,
        libc::SYS_getegid as i32,
        libc::SYS_ptrace as i32,
        libc::SYS_poll as i32,
        libc::SYS_ppoll as i32,
        libc::SYS_select as i32,
        libc::SYS_pselect6 as i32,
        libc::SYS_epoll_pwait as i32,
        libc::SYS_epoll_create1 as i32,
        libc::SYS_epoll_ctl as i32,
        libc::SYS_epoll_wait as i32,
        libc::SYS_getpgrp as i32,
        libc::SYS_getpid as i32,
        libc::SYS_getppid as i32,
        libc::SYS_arch_prctl as i32,
        libc::SYS_sched_getaffinity as i32,
        libc::SYS_socket as i32,
        libc::SYS_connect as i32,
        libc::SYS_bind as i32,
        libc::SYS_listen as i32,
        libc::SYS_accept as i32,
        libc::SYS_accept4 as i32,
        libc::SYS_sendto as i32,
        libc::SYS_recvfrom as i32,
        libc::SYS_sendmsg as i32,
        libc::SYS_recvmsg as i32,
        libc::SYS_setsockopt as i32,
        libc::SYS_getsockopt as i32,
        libc::SYS_getpeername as i32,
        libc::SYS_getsockname as i32,
        libc::SYS_shutdown as i32,
        libc::SYS_pipe as i32,
        libc::SYS_pipe2 as i32,
        libc::SYS_eventfd2 as i32,
        libc::SYS_prctl as i32,
        libc::SYS_mlock as i32,
        libc::SYS_munlock as i32,
        libc::SYS_wait4 as i32, // reap the UI child
        // Tor transport (arti): state/cache on the private tmpfs, timers, vectored I/O.
        libc::SYS_umount2 as i32, // release the tmpfs at shutdown
        libc::SYS_mkdir as i32,
        libc::SYS_mkdirat as i32,
        libc::SYS_unlink as i32,
        libc::SYS_unlinkat as i32,
        libc::SYS_rename as i32,
        libc::SYS_renameat as i32,
        libc::SYS_renameat2 as i32,
        libc::SYS_chmod as i32,
        libc::SYS_fchmod as i32,
        libc::SYS_fchmodat as i32,
        libc::SYS_fsync as i32,
        libc::SYS_fdatasync as i32,
        libc::SYS_ftruncate as i32,
        libc::SYS_fallocate as i32,
        libc::SYS_flock as i32,
        libc::SYS_getdents64 as i32,
        libc::SYS_readlink as i32,
        libc::SYS_readlinkat as i32,
        libc::SYS_pread64 as i32,
        libc::SYS_pwrite64 as i32,
        libc::SYS_readv as i32,
        libc::SYS_sched_yield as i32,
        libc::SYS_getcwd as i32,
        libc::SYS_uname as i32,
        libc::SYS_sysinfo as i32,
        libc::SYS_getrlimit as i32,
        libc::SYS_statfs as i32,
        libc::SYS_fstatfs as i32,
        libc::SYS_stat as i32,
        libc::SYS_lstat as i32,
        libc::SYS_access as i32,
        libc::SYS_faccessat as i32,
        libc::SYS_faccessat2 as i32,
        libc::SYS_utimensat as i32,
        libc::SYS_dup as i32,
        libc::SYS_dup2 as i32,
        libc::SYS_dup3 as i32,
        libc::SYS_timerfd_create as i32,
        libc::SYS_timerfd_settime as i32,
        libc::SYS_epoll_pwait2 as i32,
        libc::SYS_epoll_create as i32,
        libc::SYS_sendmmsg as i32,
        libc::SYS_recvmmsg as i32,
        libc::SYS_sched_getparam as i32,
        libc::SYS_getpriority as i32,
        libc::SYS_madvise as i32,
    ];

    for &system_call_identifier in PERMITTED_SYSTEM_CALLS {
        let kernel_syscall = ScmpSyscall::from(system_call_identifier);
        let _ = isolation_context.add_rule(ScmpAction::Allow, kernel_syscall);
    }

    isolation_context.load()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forks, applies the UI profile in the child and runs `body`; returns wait status.
    fn run_sandboxed(body: fn(i32, i32)) -> i32 {
        let mut fds = [0i32; 2];
        // SAFETY: plain libc calls; the child only uses async-signal-safe operations.
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            let pid = libc::fork();
            if pid == 0 {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                // ipc_fd = write end, tty_fd = a second dup'd descriptor
                let tty = libc::dup(fds[1]);
                if enforce(Profile::Ui { ipc_fd: fds[1], tty_fd: tty }).is_err() {
                    libc::_exit(90);
                }
                body(fds[1], tty);
                libc::_exit(0);
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            st
        }
    }

    #[test]
    fn ui_profile_allows_owned_fd_io() {
        let st = run_sandboxed(|ipc, tty| unsafe {
            libc::write(ipc, b"x".as_ptr() as *const _, 1);
            libc::write(tty, b"y".as_ptr() as *const _, 1);
        });
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "status {st}");
    }

    #[test]
    fn ui_profile_kills_on_foreign_fd_and_open() {
        let st = run_sandboxed(|_, _| unsafe {
            libc::write(2, b"x".as_ptr() as *const _, 1); // fd 2 is not allowed
        });
        assert!(libc::WIFSIGNALED(st), "status {st}");

        let st = run_sandboxed(|_, _| unsafe {
            libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY);
        });
        assert!(libc::WIFSIGNALED(st), "status {st}");

        let st = run_sandboxed(|_, _| unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        });
        assert!(libc::WIFSIGNALED(st), "status {st}");
    }
}
