use super::params::{CELL_LEN, HDR_LEN, MAX_PAYLOAD, PLAIN_LEN};
use crate::crypto::ratchet::Chain;
use zeroize::Zeroizing;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Noise = 0,
    Chat = 1,
    FileBegin = 2,
    FileData = 3,
    FileEnd = 4,
    Ctrl = 5,
}

pub const FLAG_LAST: u8 = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct Frag {
    pub kind: Kind,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frag {
    pub fn noise() -> Self {
        Frag {
            kind: Kind::Noise,
            flags: FLAG_LAST,
            payload: Vec::new(),
        }
    }
}

/// Packs a fragment into a fixed 496-byte plaintext and seals it into a 512-byte cell.
pub fn encode(chain: &mut Chain, f: &Frag) -> Result<[u8; CELL_LEN], &'static str> {
    if f.payload.len() > MAX_PAYLOAD {
        return Err("payload too large");
    }
    let mut plain = Zeroizing::new([0u8; PLAIN_LEN]);
    plain[0] = f.kind as u8;
    plain[1] = f.flags;
    plain[2..4].copy_from_slice(&(f.payload.len() as u16).to_le_bytes());
    plain[HDR_LEN..HDR_LEN + f.payload.len()].copy_from_slice(&f.payload);
    let ct = chain.seal(&plain[..])?;
    let mut out = [0u8; CELL_LEN];
    if ct.len() != CELL_LEN {
        return Err("unexpected cell size");
    }
    out.copy_from_slice(&ct);
    Ok(out)
}

/// Authenticates, decrypts and unpacks a 512-byte cell.
pub fn decode(chain: &mut Chain, wire: &[u8; CELL_LEN]) -> Result<Frag, &'static str> {
    let plain = Zeroizing::new(chain.open(wire)?);
    if plain.len() != PLAIN_LEN {
        return Err("bad plaintext size");
    }
    let len = u16::from_le_bytes([plain[2], plain[3]]) as usize;
    if len > MAX_PAYLOAD {
        return Err("bad len");
    }
    let kind = match plain[0] {
        0 => Kind::Noise,
        1 => Kind::Chat,
        2 => Kind::FileBegin,
        3 => Kind::FileData,
        4 => Kind::FileEnd,
        5 => Kind::Ctrl,
        _ => return Err("bad kind"),
    };
    Ok(Frag {
        kind,
        flags: plain[1],
        payload: plain[HDR_LEN..HDR_LEN + len].to_vec(),
    })
}

/// Source of the send/receive chains. Production uses the global session
/// (so shutdown can wipe the keys); tests use independent local chains.
pub trait CellKeys: Send + Sync {
    fn seal(&self, f: &Frag) -> Result<[u8; CELL_LEN], &'static str>;
    fn open(&self, wire: &[u8; CELL_LEN]) -> Result<Frag, &'static str>;
}

/// Independent chains held locally; used to run both peers inside one process.
#[cfg(test)]
pub struct LocalKeys {
    send: std::sync::Mutex<Chain>,
    recv: std::sync::Mutex<Chain>,
}

#[cfg(test)]
impl LocalKeys {
    pub fn new(send: [u8; 32], recv: [u8; 32]) -> Self {
        Self {
            send: std::sync::Mutex::new(Chain::new(send)),
            recv: std::sync::Mutex::new(Chain::new(recv)),
        }
    }
}

#[cfg(test)]
impl CellKeys for LocalKeys {
    fn seal(&self, f: &Frag) -> Result<[u8; CELL_LEN], &'static str> {
        encode(&mut self.send.lock().unwrap(), f)
    }
    fn open(&self, wire: &[u8; CELL_LEN]) -> Result<Frag, &'static str> {
        decode(&mut self.recv.lock().unwrap(), wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Chain, Chain) {
        (Chain::new([7u8; 32]), Chain::new([7u8; 32]))
    }

    #[test]
    fn roundtrip_and_fixed_size() {
        let (mut tx, mut rx) = pair();
        for payload in [vec![], b"hi".to_vec(), vec![0xAB; MAX_PAYLOAD]] {
            let f = Frag { kind: Kind::Chat, flags: FLAG_LAST, payload };
            let cell = encode(&mut tx, &f).unwrap();
            assert_eq!(cell.len(), CELL_LEN);
            assert_eq!(decode(&mut rx, &cell).unwrap(), f);
        }
    }

    #[test]
    fn noise_is_same_size_and_decodes_as_noise() {
        let (mut tx, mut rx) = pair();
        let cell = encode(&mut tx, &Frag::noise()).unwrap();
        assert_eq!(decode(&mut rx, &cell).unwrap().kind, Kind::Noise);
    }

    #[test]
    fn oversize_rejected() {
        let (mut tx, _) = pair();
        let f = Frag { kind: Kind::Chat, flags: 0, payload: vec![0; MAX_PAYLOAD + 1] };
        assert!(encode(&mut tx, &f).is_err());
    }

    #[test]
    fn tamper_rejected() {
        let (mut tx, mut rx) = pair();
        let f = Frag { kind: Kind::Chat, flags: FLAG_LAST, payload: b"x".to_vec() };
        let mut cell = encode(&mut tx, &f).unwrap();
        cell[10] ^= 1;
        assert!(decode(&mut rx, &cell).is_err());
    }
}
