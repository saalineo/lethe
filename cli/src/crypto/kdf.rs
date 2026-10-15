use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_message_and_chain_keys(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), &'static str> {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut message_key = [0u8; 32];
    let mut next_chain_key = [0u8; 32];
    hk.expand(b"msg", &mut message_key).map_err(|_| "HKDF expand failed for message key")?;
    hk.expand(b"chain", &mut next_chain_key).map_err(|_| "HKDF expand failed for chain key")?;
    Ok((message_key, next_chain_key))
}
