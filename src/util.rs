use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, Copy, Clone, Hash)]
pub enum MacDigest {
    SHA1,
    SHA256,
    SHA512
}

pub(crate) fn get_code(bytes: [u8; 4], digits: u32) -> u32 {
    let code = (((bytes[0] & 0x7f) as u32) << 24)
        | (((bytes[1] & 0xff) as u32) << 16)
        | (((bytes[2] & 0xff) as u32) << 8)
        | (bytes[3] & 0xff) as u32;
    code % (10_u32.pow(digits))
}

pub(crate) fn hash_generic(msg: &[u8], secret: &[u8], digest: &MacDigest) -> Vec<u8> {
    match *digest {
        MacDigest::SHA1 => hash_internal::<Hmac<Sha1>>(msg, secret),
        MacDigest::SHA256 => hash_internal::<Hmac<Sha256>>(msg, secret),
        MacDigest::SHA512 => hash_internal::<Hmac<Sha512>>(msg, secret)
    }
}

fn hash_internal<D: Mac> (msg: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut hmac = <D>::new_from_slice(secret)
        .expect("Failed to initialize HMAC");
    hmac.update(msg);
    hmac.finalize().into_bytes()[..].into()
}
