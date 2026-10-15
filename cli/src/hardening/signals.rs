use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::thread;

use crate::shutdown::secure_shutdown;

pub fn install_signal_handlers() -> Result<(), Box<dyn std::error::Error>> {
    let mut signals = Signals::new([SIGINT, SIGTERM])?;

    thread::spawn(move || {
        for _ in signals.forever() {
            secure_shutdown();
        }
    });
    Ok(())
}
