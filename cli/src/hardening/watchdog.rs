use libc::{
    fork, kill, ptrace, waitpid, PTRACE_CONT, PTRACE_TRACEME, SIGKILL,
    WEXITSTATUS, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WSTOPSIG, WTERMSIG,
};
use std::process;

pub fn secure_launch<F>(sandbox_payload: F)
where
    F: FnOnce() -> Result<(), Box<dyn std::error::Error>>,
{
    // SAFETY: Process fork and ptrace monitoring loop using standard OS APIs.
    unsafe {
        let child_process_id = fork();

        if child_process_id < 0 {
            process::exit(1);
        }

        if child_process_id == 0 {
            if ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 {
                process::exit(1);
            }

            if sandbox_payload().is_err() {
                process::exit(1);
            }

            process::exit(0);
        } else {
            loop {
                let mut child_execution_status = 0;
                waitpid(child_process_id, &mut child_execution_status, 0);

                if WIFEXITED(child_execution_status) {
                    process::exit(WEXITSTATUS(child_execution_status));
                }

                if WIFSIGNALED(child_execution_status) {
                    crate::status_ln!(
                        "\n[!] Watchdog Alert: Child terminated by signal {}",
                        WTERMSIG(child_execution_status)
                    );
                    process::exit(1);
                }

                if WIFSTOPPED(child_execution_status) {
                    let sig = WSTOPSIG(child_execution_status);
                    match sig {
                        libc::SIGSYS | libc::SIGSEGV | libc::SIGILL
                        | libc::SIGBUS | libc::SIGABRT | libc::SIGFPE => {
                            crate::status_ln!(
                                "\n[!] Watchdog Alert: Child killed by signal {} (security violation)",
                                sig
                            );
                            let _ = kill(child_process_id, SIGKILL);
                            process::exit(1);
                        }
                        _ => {
                            if ptrace(PTRACE_CONT, child_process_id, 0, sig) < 0 {
                                let _ = kill(child_process_id, SIGKILL);
                                process::exit(1);
                            }
                        }
                    }
                    continue;
                }

                if ptrace(PTRACE_CONT, child_process_id, 0, 0) < 0 {
                    let _ = kill(child_process_id, SIGKILL);
                    process::exit(1);
                }
            }
        }
    }
}
