/// Operating mode, derived from where stdin/stdout point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Interactive chat (stdin and stdout are terminals).
    Chat,
    /// `cat f | lethe`: stream stdin to the peer.
    SendStdin,
    /// `lethe > f`: stream the peer's file to stdout.
    RecvStdout,
}

/// Pure decision table, separated from the libc probes for testability.
pub fn classify(in_tty: bool, out_tty: bool) -> Mode {
    match (in_tty, out_tty) {
        (true, true) => Mode::Chat,
        (false, _) => Mode::SendStdin,
        (true, false) => Mode::RecvStdout,
    }
}

/// Auto-detects the mode; `--send` / `--recv` override it.
pub fn detect(args: &[String]) -> Mode {
    if args.iter().any(|a| a == "--send") {
        return Mode::SendStdin;
    }
    if args.iter().any(|a| a == "--recv") {
        return Mode::RecvStdout;
    }
    // SAFETY: isatty only inspects the given descriptor.
    let in_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    let out_tty = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
    classify(in_tty, out_tty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_table() {
        assert_eq!(classify(true, true), Mode::Chat);
        assert_eq!(classify(false, true), Mode::SendStdin);
        assert_eq!(classify(false, false), Mode::SendStdin);
        assert_eq!(classify(true, false), Mode::RecvStdout);
    }

    #[test]
    fn explicit_overrides() {
        let a = |s: &str| vec!["lethe".to_string(), s.to_string()];
        assert_eq!(detect(&a("--send")), Mode::SendStdin);
        assert_eq!(detect(&a("--recv")), Mode::RecvStdout);
    }
}
