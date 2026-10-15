//! Sandboxed terminal UI: a single-threaded `poll` loop over the tty and the
//! IPC socket. It never sees keys or the network and needs no `clone`/`open`.

use crate::ipc::{self, CoreToUi, MAX_FRAME, UiToCore};
use crate::username::{self, Prompter};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use zeroize::Zeroize;

const LINE_MAX: usize = 1024;

// ---------------------------------------------------------------------------
// Terminal state saved for restoration from every exit path (incl. signals).
// ---------------------------------------------------------------------------

struct SavedTermios(UnsafeCell<MaybeUninit<libc::termios>>);
// SAFETY: written once before SAVED_SET is published; afterwards read-only.
unsafe impl Sync for SavedTermios {}

static SAVED: SavedTermios = SavedTermios(UnsafeCell::new(MaybeUninit::uninit()));
static SAVED_SET: AtomicBool = AtomicBool::new(false);
static TTY_FD: AtomicI32 = AtomicI32::new(-1);

/// Puts the tty in no-echo, non-canonical, no-signal mode and remembers the old state.
fn enter_raw(fd: i32) -> bool {
    // SAFETY: tcgetattr fully initialises the struct on success.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return false;
        }
        (*SAVED.0.get()).write(t);
        SAVED_SET.store(true, Ordering::SeqCst);
        TTY_FD.store(fd, Ordering::SeqCst);
        t.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        libc::tcsetattr(fd, libc::TCSAFLUSH, &t) == 0
    }
}

/// Async-signal-safe: restores the saved terminal state if one was captured.
fn restore_termios() {
    if SAVED_SET.swap(false, Ordering::SeqCst) {
        let fd = TTY_FD.load(Ordering::SeqCst);
        // SAFETY: SAVED was initialised before SAVED_SET became true.
        unsafe {
            let t = (*SAVED.0.get()).assume_init_ref();
            libc::tcsetattr(fd, libc::TCSAFLUSH, t);
        }
    }
}

extern "C" fn on_signal(_: libc::c_int) {
    restore_termios();
    // SAFETY: async-signal-safe immediate exit.
    unsafe { libc::_exit(0) };
}

/// Installs handlers (before seccomp is loaded) so SIGINT/SIGTERM/SIGHUP/SIGQUIT
/// restore the terminal instead of leaving it raw.
pub fn install_restore_handlers() {
    // SAFETY: sigaction with a zeroed, then filled-in, struct.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

fn leave(code: i32) -> ! {
    restore_termios();
    // SAFETY: terminate without running destructors in the forked UI.
    unsafe { libc::_exit(code) }
}

// ---------------------------------------------------------------------------
// Raw tty I/O (libc only: the sandbox allows read/write on exactly two fds).
// ---------------------------------------------------------------------------

fn tty_write(fd: i32, mut s: &[u8]) {
    while !s.is_empty() {
        // SAFETY: s is a valid slice.
        let n = unsafe { libc::write(fd, s.as_ptr() as *const _, s.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        s = &s[n as usize..];
    }
}

/// Renders untrusted bytes as printable text: invalid UTF-8 and control
/// characters (including ESC) can never reach the terminal.
pub fn sanitize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn prompt_text(alias: &str) -> String {
    format!(
        "\x1b[1;31m[\x1b[0m\x1b[1;35m{alias}@lethe\x1b[0m\x1b[1;31m]\x1b[0m\x1b[1;34m~\x1b[0m\x1b[1;31m#\x1b[0m "
    )
}

/// Clears the current input row, prints `text` above it, then redraws prompt + partial input.
fn redraw_with_message(fd: i32, alias: &str, line: &[u8], text: &str) {
    let mut out = String::new();
    out.push_str("\r\x1b[K");
    out.push_str(text);
    out.push('\n');
    out.push_str(&prompt_text(alias));
    tty_write(fd, out.as_bytes());
    tty_write(fd, &sanitize_keep_len(line));
}

/// Like `sanitize` but returns bytes (typed line is already echoed this way).
fn sanitize_keep_len(line: &[u8]) -> Vec<u8> {
    sanitize(line).into_bytes()
}

// ---------------------------------------------------------------------------
// Poll helpers
// ---------------------------------------------------------------------------

/// What woke the loop up.
enum Event {
    Tty,
    Ipc,
    Hangup,
}

fn wait(tty_fd: i32, ipc_fd: i32) -> Event {
    loop {
        let mut fds = [
            libc::pollfd { fd: tty_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: ipc_fd, events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: fds is a valid array of two pollfd.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            continue; // EINTR
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            return Event::Ipc;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            return Event::Tty;
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Event::Hangup;
        }
    }
}

fn read_byte(fd: i32) -> Option<u8> {
    let mut b = 0u8;
    loop {
        // SAFETY: reads one byte into a valid stack variable.
        let n = unsafe { libc::read(fd, &mut b as *mut u8 as *mut _, 1) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return if n == 1 { Some(b) } else { None };
    }
}

/// Alias questionnaire on the tty while still watching the IPC socket.
struct UiPrompter<'a> {
    tty_fd: i32,
    ipc: &'a mut UnixStream,
}

impl Prompter for UiPrompter<'_> {
    fn write(&mut self, s: &str) {
        tty_write(self.tty_fd, s.as_bytes());
    }

    fn read_line(&mut self) -> Option<String> {
        let mut line = Vec::new();
        let mut buf = [0u8; MAX_FRAME];
        loop {
            match wait(self.tty_fd, self.ipc.as_raw_fd()) {
                Event::Ipc => match ipc::recv(self.ipc, &mut buf) {
                    Ok((t, _)) if t == CoreToUi::Shutdown as u8 => leave(0),
                    Ok(_) => {}
                    Err(_) => leave(0),
                },
                Event::Hangup => leave(0),
                Event::Tty => {
                    let b = read_byte(self.tty_fd)?;
                    match b {
                        b'\n' | b'\r' => {
                            tty_write(self.tty_fd, b"\n");
                            return Some(String::from_utf8_lossy(&line).into_owned());
                        }
                        0x03 | 0x04 => leave(0),
                        0x7f | 0x08 => {
                            if line.pop().is_some() {
                                tty_write(self.tty_fd, b"\x08 \x08");
                            }
                        }
                        0x20..=0x7e if line.len() < 16 => {
                            line.push(b);
                            tty_write(self.tty_fd, &[b]);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

/// Input escape-sequence skipper (arrow keys etc. must not enter the line).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Esc {
    None,
    Got,    // saw ESC
    Params, // inside CSI/SS3 until a final byte
}

pub fn run(mut ipc: UnixStream, tty_fd: i32) -> ! {
    let ipc_fd = ipc.as_raw_fd();
    let mut buf = [0u8; MAX_FRAME];

    // The core owns the terminal until the handshake is done.
    loop {
        match ipc::recv(&mut ipc, &mut buf) {
            Ok((t, _)) if t == CoreToUi::Ready as u8 => break,
            Ok((t, _)) if t == CoreToUi::Shutdown as u8 => leave(0),
            Ok(_) => {}
            Err(_) => leave(0),
        }
    }

    if !enter_raw(tty_fd) {
        leave(1);
    }

    let alias = {
        let mut p = UiPrompter { tty_fd, ipc: &mut ipc };
        username::generate_username_with(&mut p)
    };
    tty_write(
        tty_fd,
        format!("\n\x1b[1;30m[+]\x1b[0m \x1b[32mAssigned Alias: {alias}\x1b[0m\n\n").as_bytes(),
    );
    if ipc::send(&mut ipc, UiToCore::Hello as u8, alias.as_bytes()).is_err() {
        leave(0);
    }

    let mut line = [0u8; LINE_MAX];
    let mut len = 0usize;
    let mut esc = Esc::None;
    tty_write(tty_fd, prompt_text(&alias).as_bytes());

    'main: loop {
        match wait(tty_fd, ipc_fd) {
            Event::Hangup => break,
            Event::Ipc => match ipc::recv(&mut ipc, &mut buf) {
                Ok((t, n)) if t == CoreToUi::Peer as u8 => {
                    let msg = format!(
                        "\x1b[1;30m[\x1b[0m\x1b[1;32mPEER\x1b[0m\x1b[1;30m]\x1b[0m \x1b[32m{}\x1b[0m",
                        sanitize(&buf[..n])
                    );
                    redraw_with_message(tty_fd, &alias, &line[..len], &msg);
                }
                Ok((t, n)) if t == CoreToUi::Status as u8 => {
                    let msg = format!("\x1b[1;30m[+]\x1b[0m {}", sanitize(&buf[..n]));
                    redraw_with_message(tty_fd, &alias, &line[..len], &msg);
                }
                Ok((t, _)) if t == CoreToUi::Shutdown as u8 => break,
                Ok(_) => {}
                Err(_) => break, // core died
            },
            Event::Tty => {
                let Some(b) = read_byte(tty_fd) else { break };
                match esc {
                    Esc::Got => {
                        esc = if b == b'[' || b == b'O' { Esc::Params } else { Esc::None };
                        continue 'main;
                    }
                    Esc::Params => {
                        if (0x40..=0x7e).contains(&b) {
                            esc = Esc::None;
                        }
                        continue 'main;
                    }
                    Esc::None => {}
                }
                match b {
                    0x1b => esc = Esc::Got,
                    b'\n' | b'\r' => {
                        let msg = &line[..len];
                        if msg.eq_ignore_ascii_case(b"exit") || msg.eq_ignore_ascii_case(b"quit") {
                            let _ = ipc::send(&mut ipc, UiToCore::Quit as u8, &[]);
                            break;
                        }
                        if !msg.is_empty() {
                            let _ = ipc::send(&mut ipc, UiToCore::Line as u8, msg);
                        }
                        line.zeroize();
                        len = 0;
                        tty_write(tty_fd, b"\r\x1b[K");
                        tty_write(tty_fd, prompt_text(&alias).as_bytes());
                    }
                    0x03 | 0x04 => {
                        let _ = ipc::send(&mut ipc, UiToCore::Quit as u8, &[]);
                        break;
                    }
                    0x7f | 0x08 => {
                        // Drop one character (UTF-8 aware) and erase it on screen.
                        while len > 0 && (line[len - 1] & 0xC0) == 0x80 {
                            len -= 1;
                            line[len] = 0;
                        }
                        if len > 0 {
                            len -= 1;
                            line[len] = 0;
                            tty_write(tty_fd, b"\x08 \x08");
                        }
                    }
                    c if c >= 0x20 && len < LINE_MAX => {
                        line[len] = c;
                        len += 1;
                        // Echo the raw byte so multibyte characters assemble on screen.
                        tty_write(tty_fd, &[c]);
                    }
                    _ => {}
                }
            }
        }
    }
    line.zeroize();
    leave(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_escapes_and_controls() {
        assert_eq!(sanitize(b"hi\x1b[31mred\x07\r\n"), "hi?[31mred???");
        assert_eq!(sanitize("héllo".as_bytes()), "héllo");
        assert_eq!(sanitize(b"\xff\xfe"), "\u{FFFD}\u{FFFD}");
    }
}
