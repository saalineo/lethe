use libc::{prctl, rlimit, setrlimit, PR_SET_DUMPABLE, RLIMIT_CORE};
use std::io;

pub fn disable_core_dumps() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE and RLIMIT_CORE call standard libc APIs with valid zeroed limits.
    unsafe {
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }

        let limit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if setrlimit(RLIMIT_CORE, &limit) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
