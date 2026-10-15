use crate::chat::router::HostRouter;
use crate::hardening::input::RawTerminal;

pub fn run(router: HostRouter) {
    let my_username = crate::username::generate_username();
    if !crate::username::is_pipe_mode() {
        eprintln!(
            "\n\x1b[1;30m[+]\x1b[0m \x1b[32mAssigned Alias: {}\x1b[0m\n",
            my_username
        );
    }

    let _raw = RawTerminal::enter();

    let (queue_tx, queue_rx) = std::sync::mpsc::sync_channel(super::send_loop::QUEUE_DEPTH);
    super::send_loop::spawn_scheduler(queue_rx, router.transport());
    super::recv_loop::spawn(router.transport(), my_username.clone());
    super::send_loop::run(queue_tx, &my_username);
}
