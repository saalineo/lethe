#[cfg(not(debug_assertions))]
use std::fs;
#[cfg(not(debug_assertions))]
use std::process;

#[cfg(not(debug_assertions))]
pub fn block_debugger() {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("TracerPid:") {
            let tracer_pid: i64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if tracer_pid != 0 {
                process::exit(1);
            }
            return;
        }
    }
}

#[cfg(debug_assertions)]
pub fn block_debugger() {
    eprintln!("\x1b[1;33m[WARN] Debug mode enabled: Anti-tamper/Debugger checks bypassed.\x1b[0m");
}
