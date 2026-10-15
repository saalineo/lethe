use libc::{tcgetattr, tcsetattr, termios, ECHO, ICANON, STDIN_FILENO, TCSANOW};
use std::io::{self, Read};

pub struct RawTerminal {
    original: termios,
}

impl RawTerminal {
    pub fn enter() -> Self {
        // SAFETY: zeroed termios initialized before tcgetattr fills it.
        let mut original: termios = unsafe { std::mem::zeroed() };
        unsafe {
            tcgetattr(STDIN_FILENO, &mut original);

            let mut raw = original;
            raw.c_lflag &= !(ICANON | ECHO);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        }

        Self { original }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        // SAFETY: Restores saved termios settings.
        unsafe {
            tcsetattr(STDIN_FILENO, TCSANOW, &self.original);
        }
    }
}

pub fn read_line_raw() -> String {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];

    loop {
        if io::stdin().read_exact(&mut byte).is_err() {
            break;
        }
        match byte[0] {
            b'\n' | b'\r' => break,
            b'\x7f' | b'\x08' => {
                if !buf.is_empty() {
                    buf.pop();
                }
            }
            b => buf.push(b),
        }
    }

    String::from_utf8_lossy(&buf).into_owned()
}
