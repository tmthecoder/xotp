use hmac::digest::DynDigest;
use hmac::{Hmac, Mac, SimpleHmac};
use hmac::digest::core_api::{CoreProxy, FixedOutputCore};
use hmac::digest::crypto_common::BlockSizeUser;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

pub(crate) fn get_code(bytes: [u8; 4], digits: u32) -> u32 {
    let code = (((bytes[0] & 0x7f) as u32) << 24)
        | (((bytes[1] & 0xff) as u32) << 16)
        | (((bytes[2] & 0xff) as u32) << 8)
        | (bytes[3] & 0xff) as u32;
    code & (10_u32.pow(digits))
}

pub(crate) fn hash_sha1(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    hash_generic::<Hmac<Sha1>>(msg, secret)
}

fn hash_sha256(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    hash_generic::<Hmac<Sha256>>(msg, secret)
}

fn hash_sha512(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    hash_generic::<Hmac<Sha512>>(msg, secret)
}

fn hash_generic<D: Mac>(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut hmac = <D>::new_from_slice(secret)
        .expect("Failed to initialize HMAC");
    hmac.update(msg);
    hmac.finalize().into_bytes()[..].into()
}
