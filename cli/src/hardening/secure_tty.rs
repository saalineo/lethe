use crate::crypto::secret::SecretBuf;
use libc::{
    ECHO, ECHONL, ICANON, O_CLOEXEC, O_NOCTTY, O_RDWR, TCSAFLUSH, VMIN, VTIME, open, read,
    tcgetattr, tcsetattr, termios, write,
};
use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

/// Terminal state to restore on abnormal exit paths (signals, panic hook),
/// since `process::exit` skips destructors.
static SAVED_TERMIOS: Mutex<Option<(libc::c_int, termios)>> = Mutex::new(None);

/// Restores the terminal settings saved by an active [`EchoOff`] guard, if any.
pub fn restore_saved_termios() {
    let mut g = SAVED_TERMIOS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((fd, saved)) = g.take() {
        // SAFETY: fd/termios were captured from a successful tcgetattr.
        unsafe { tcsetattr(fd, TCSAFLUSH, &saved) };
    }
}

/// Handle to the controlling terminal, opened directly (never fd 0/1/2).
pub struct Tty {
    fd: libc::c_int,
}

impl Tty {
    pub fn open() -> io::Result<Self> {
        // SAFETY: path is a valid NUL-terminated C string.
        let fd = unsafe {
            open(
                c"/dev/tty".as_ptr(),
                O_RDWR | O_NOCTTY | O_CLOEXEC,
            )
        };
        if fd < 0 {
            // No controlling terminal: refuse.
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    pub fn write_all(&self, mut s: &[u8]) {
        while !s.is_empty() {
            // SAFETY: s points to s.len() valid bytes.
            let n = unsafe { write(self.fd, s.as_ptr() as *const _, s.len()) };
            if n < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            s = &s[n as usize..];
        }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this handle.
        unsafe { libc::close(self.fd) };
    }
}

/// Disables echo and canonical mode; restores the terminal on every exit path,
/// including panic unwinding.
struct EchoOff {
    fd: libc::c_int,
    saved: termios,
}

impl EchoOff {
    fn new(fd: libc::c_int) -> io::Result<Self> {
        // SAFETY: termios is plain data, filled in by tcgetattr before use.
        unsafe {
            let mut saved: termios = std::mem::zeroed();
            if tcgetattr(fd, &mut saved) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut raw = saved;
            raw.c_lflag &= !(ECHO | ECHONL | ICANON);
            raw.c_cc[VMIN] = 1;
            raw.c_cc[VTIME] = 0;
            if tcsetattr(fd, TCSAFLUSH, &raw) != 0 {
                return Err(io::Error::last_os_error());
            }
            *SAVED_TERMIOS.lock().unwrap_or_else(|p| p.into_inner()) = Some((fd, saved));
            Ok(Self { fd, saved })
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the settings captured in `new`.
        unsafe { tcsetattr(self.fd, TCSAFLUSH, &self.saved) };
        *SAVED_TERMIOS.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// Reads a secret byte-by-byte from the tty into a locked, zeroizing buffer.
pub fn read_secret(tty: &Tty, prompt: &str) -> io::Result<SecretBuf> {
    tty.write_all(prompt.as_bytes());
    let _guard = EchoOff::new(tty.fd)?;
    let mut out = SecretBuf::new();
    let mut b = 0u8;
    let result = loop {
        // SAFETY: reads at most 1 byte into a valid stack byte.
        let n = unsafe { read(tty.fd, &mut b as *mut u8 as *mut _, 1) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            break Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tty closed"));
        }
        match b {
            b'\n' | b'\r' => break Ok(()),
            0x7f | 0x08 => out.pop(),
            0x03 | 0x04 => {
                break Err(io::Error::new(io::ErrorKind::Interrupted, "aborted"));
            }
            0x20..=0x7e | 0x80..=0xff => {
                out.push(b);
            }
            _ => {}
        }
    };
    b.zeroize();
    tty.write_all(b"\n");
    result.map(|()| out)
}

/// Controlling terminal used for status lines (opened once, lazily).
static STATUS_TTY: OnceLock<Option<Tty>> = OnceLock::new();

/// Writes a status/diagnostic line to the controlling terminal, falling back
/// to stderr. stdout/stdin are reserved for data in file-transfer modes.
pub fn status(msg: &str) {
    match STATUS_TTY.get_or_init(|| Tty::open().ok()) {
        Some(tty) => tty.write_all(msg.as_bytes()),
        None => {
            let _ = io::stderr().write_all(msg.as_bytes());
        }
    }
}

/// `eprintln!` replacement that prefers the tty over stderr.
#[macro_export]
macro_rules! status_ln {
    () => {
        $crate::hardening::secure_tty::status("\n")
    };
    ($($arg:tt)*) => {
        $crate::hardening::secure_tty::status(&format!("{}\n", format_args!($($arg)*)))
    };
}
