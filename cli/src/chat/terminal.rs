use crate::chat::router::HostRouter;
use crate::crypto::ratchet::RatchetState;
use crate::hardening::input::RawTerminal;
use std::sync::{Arc, Mutex};

pub fn run(
    router: HostRouter,
    mut send_ratchet: RatchetState,
    recv_ratchet: Arc<Mutex<RatchetState>>,
    my_username: String,
) {
    let _raw = RawTerminal::enter();

    super::recv_loop::spawn(router.inner(), recv_ratchet, my_username.clone());
    super::send_loop::run(&router, &mut send_ratchet, &my_username);
}
