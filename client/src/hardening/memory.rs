use libc::{mlockall, munlockall, MCL_CURRENT, MCL_FUTURE};
use std::fmt;

#[derive(Debug)]
pub enum SecurityError {
    MemoryLockFailed(i32),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::MemoryLockFailed(code) => write!(f, "Memory lock failed with OS code {}", code),
        }
    }
}

impl std::error::Error for SecurityError {}

pub fn lock_memory() -> Result<(), SecurityError> {
    // SAFETY: Calling mlockall with valid flags to lock pages in memory.
    let ret = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
    if ret != 0 {
        return Err(SecurityError::MemoryLockFailed(ret));
    }
    Ok(())
}

pub fn unlock_memory() {
    // SAFETY: munlockall is safe to invoke for the current process.
    unsafe {
        munlockall();
    }
}