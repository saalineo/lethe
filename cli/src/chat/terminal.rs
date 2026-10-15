//! Core-side bridge between the sandboxed UI (IPC) and the network queue.
//!
//! The core never touches the terminal: lines arrive as `UiToCore::Line`,
//! peer messages leave as `CoreToUi::Peer`. Everything from the UI is hostile.

use std::os::unix::net::UnixStream;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use crate::chat::router::HostRouter;
use crate::hardening::sandbox_ui;
use crate::ipc::{self, CoreToUi, MAX_FRAME, UiToCore};
use crate::proto::cell::{Frag, Kind};
use crate::proto::frame;

/// Longest alias accepted from the UI (bytes).
const ALIAS_MAX: usize = 64;
/// Peer messages held back until the UI has announced its alias.
const HELD_MAX: usize = 64;

/// Holds peer messages until the UI has finished its questionnaire.
#[derive(Default)]
struct Gate {
    ready: bool,
    held: Vec<Vec<u8>>,
}

fn forward_to_ui(msg: &[u8]) {
    for chunk in msg.chunks(MAX_FRAME) {
        sandbox_ui::send_to_ui(CoreToUi::Peer as u8, chunk);
    }
}

/// Makes an alias safe to embed in outgoing text (no control characters).
fn clean_alias(raw: &[u8]) -> String {
    let s: String = String::from_utf8_lossy(raw)
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect();
    let mut s = s.trim().to_string();
    while s.len() > ALIAS_MAX {
        s.pop();
    }
    if s.is_empty() { "anon".to_string() } else { s }
}

/// Builds the on-wire chat text for a UI line.
fn chat_text(alias: &str, line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(alias.len() + 2 + line.len());
    out.extend_from_slice(alias.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(line);
    out
}

/// Reads UI frames until the UI quits or dies, then shuts the core down.
fn pump_ui(mut ui: UnixStream, queue: SyncSender<Frag>, gate: Arc<Mutex<Gate>>) {
    let mut buf = [0u8; MAX_FRAME];
    let mut alias: Option<String> = None;
    loop {
        let (tag, n) = match ipc::recv(&mut ui, &mut buf) {
            Ok(v) => v,
            Err(_) => break, // UI exited or died
        };
        match tag {
            t if t == UiToCore::Hello as u8 => {
                if alias.is_none() {
                    alias = Some(clean_alias(&buf[..n]));
                    let mut g = gate.lock().unwrap_or_else(|p| p.into_inner());
                    g.ready = true;
                    for m in g.held.drain(..) {
                        forward_to_ui(&m);
                    }
                }
            }
            t if t == UiToCore::Line as u8 => {
                // Backpressure: the bounded queue throttles a flooding UI.
                let text = chat_text(alias.as_deref().unwrap_or("anon"), &buf[..n]);
                for f in frame::fragment(Kind::Chat, &text) {
                    if queue.send(f).is_err() {
                        return;
                    }
                }
            }
            t if t == UiToCore::Quit as u8 => break,
            _ => {} // unknown tags are ignored
        }
    }
    crate::shutdown::secure_shutdown();
}

pub fn run(router: HostRouter, ui: UnixStream, ui_pid: libc::pid_t) {
    // The core no longer needs the terminal: the UI takes over from here.
    crate::hardening::secure_tty::close_status_tty();
    let writer = match ui.try_clone() {
        Ok(w) => w,
        Err(_) => return crate::shutdown::secure_shutdown(),
    };
    sandbox_ui::attach(writer, ui_pid);
    if !sandbox_ui::send_to_ui(CoreToUi::Ready as u8, &[]) {
        return crate::shutdown::secure_shutdown();
    }

    let gate = Arc::new(Mutex::new(Gate::default()));
    let (queue_tx, queue_rx) = std::sync::mpsc::sync_channel(super::send_loop::QUEUE_DEPTH);
    super::send_loop::spawn_scheduler(
        queue_rx,
        router.transport(),
        Arc::new(crate::crypto::secret::GlobalSession),
        Some(0),
    );

    let rx_gate = Arc::clone(&gate);
    super::recv_loop::spawn(
        router.transport(),
        Arc::new(move |msg: &[u8]| {
            let mut g = rx_gate.lock().unwrap_or_else(|p| p.into_inner());
            if g.ready {
                forward_to_ui(msg);
            } else if g.held.len() < HELD_MAX {
                g.held.push(msg.to_vec());
            }
        }),
    );

    // This thread becomes the UI -> network pump.
    pump_ui(ui, queue_tx, gate);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_is_sanitised_and_bounded() {
        assert_eq!(clean_alias(b"gh0st"), "gh0st");
        assert_eq!(clean_alias(b"a\x1b[31mb"), "a_[31mb");
        assert_eq!(clean_alias(b"   "), "anon");
        assert_eq!(clean_alias(&vec![b'x'; 500]).len(), ALIAS_MAX);
    }

    #[test]
    fn chat_text_is_alias_prefixed_and_binary_safe() {
        assert_eq!(chat_text("me", b"hi\xff"), b"me: hi\xff".to_vec());
    }
}
