use super::cell::{FLAG_LAST, Frag, Kind};
use super::params::{MAX_MESSAGE, MAX_PAYLOAD};

/// Splits `data` into cells; the final one carries `FLAG_LAST`.
pub fn fragment(kind: Kind, data: &[u8]) -> Vec<Frag> {
    if data.is_empty() {
        return vec![Frag { kind, flags: FLAG_LAST, payload: Vec::new() }];
    }
    let n = data.chunks(MAX_PAYLOAD).count();
    data.chunks(MAX_PAYLOAD)
        .enumerate()
        .map(|(i, c)| Frag {
            kind,
            flags: if i + 1 == n { FLAG_LAST } else { 0 },
            payload: c.to_vec(),
        })
        .collect()
}

/// Reassembles fragments of one message at a time.
#[derive(Default)]
pub struct Reassembler {
    kind: Option<Kind>,
    buf: Vec<u8>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a fragment. Returns the complete message when `FLAG_LAST` arrives.
    /// An error is fatal for the session (kind switch mid-message or size cap).
    pub fn push(&mut self, f: Frag) -> Result<Option<(Kind, Vec<u8>)>, &'static str> {
        match self.kind {
            Some(k) if k != f.kind => return Err("interleaved message kinds"),
            _ => self.kind = Some(f.kind),
        }
        if self.buf.len() + f.payload.len() > MAX_MESSAGE {
            return Err("message too large");
        }
        self.buf.extend_from_slice(&f.payload);
        if f.flags & FLAG_LAST != 0 {
            let kind = self.kind.take().expect("kind set above");
            return Ok(Some((kind, std::mem::take(&mut self.buf))));
        }
        Ok(None)
    }
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_single_last_cell() {
        let v = fragment(Kind::Chat, b"");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].flags, FLAG_LAST);
    }

    #[test]
    fn exact_boundary_and_split() {
        assert_eq!(fragment(Kind::Chat, &vec![1; MAX_PAYLOAD]).len(), 1);
        let v = fragment(Kind::Chat, &vec![1; MAX_PAYLOAD + 1]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].flags, 0);
        assert_eq!(v[1].flags, FLAG_LAST);
    }

    #[test]
    fn reassemble_roundtrip() {
        let data: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        let mut r = Reassembler::new();
        let mut out = None;
        for f in fragment(Kind::Chat, &data) {
            out = r.push(f).unwrap();
        }
        assert_eq!(out, Some((Kind::Chat, data)));
    }

    #[test]
    fn cap_and_interleave_fail() {
        let mut r = Reassembler::new();
        let big = Frag { kind: Kind::Chat, flags: 0, payload: vec![0; MAX_PAYLOAD] };
        let mut err = None;
        for _ in 0..(MAX_MESSAGE / MAX_PAYLOAD + 2) {
            if let Err(e) = r.push(Frag { kind: big.kind, flags: 0, payload: big.payload.clone() }) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(err, Some("message too large"));

        let mut r = Reassembler::new();
        r.push(Frag { kind: Kind::Chat, flags: 0, payload: vec![1] }).unwrap();
        assert!(r.push(Frag { kind: Kind::FileData, flags: 0, payload: vec![1] }).is_err());
    }
}
