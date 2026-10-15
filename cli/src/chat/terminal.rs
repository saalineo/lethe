use crate::chat::router::HostRouter;
use crate::hardening::input::RawTerminal;

pub fn run(router: HostRouter, my_username: String) {
    let _raw = RawTerminal::enter();

    super::recv_loop::spawn(router.inner(), my_username.clone());
    super::send_loop::run(&router, &my_username);
}
