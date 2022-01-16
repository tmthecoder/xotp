use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// The digest to use with TOTP
///
/// All three digests referenced in [RFC6238] are supported:
/// - SHA1
/// - SHA256
/// - SHA512
///
/// SHA1 is still primarily used, and some other authenticator applications
/// may not support other digest algorithms.
///
/// [RFC6238]: https://datatracker.ietf.org/doc/html/rfc6238

#[derive(Debug, Copy, Clone, Hash)]
pub enum MacDigest {
    SHA1,
    SHA256,
    SHA512,
}

/// A generic method to convert the [H/T]OTP byte-array into the
/// requested decimal-based code
///
/// Needs the bytes to convert and the amount of digits the code should be

pub(crate) fn get_code(bytes: [u8; 4], digits: u32) -> u32 {
    let code = (((bytes[0] & 0x7f) as u32) << 24)
        | ((bytes[1] as u32) << 16)
        | ((bytes[2] as u32) << 8)
        | bytes[3] as u32;
    code % (10_u32.pow(digits))
}

/// A method to hash a message with a given secret and digest.
///
/// The only time [`MacDigest`] is not [`MacDigest::SHA1`] is when the
/// TOTP instance's mac_digest is set otherwise
///
/// Calls the underlying [`hash_internal`] function with the correctly
/// HMAC-mapped algorithm.

pub(crate) fn hash_generic(msg: &[u8], secret: &[u8], digest: &MacDigest) -> Vec<u8> {
    match *digest {
        MacDigest::SHA1 => hash_internal::<Hmac<Sha1>>(msg, secret),
        MacDigest::SHA256 => hash_internal::<Hmac<Sha256>>(msg, secret),
        MacDigest::SHA512 => hash_internal::<Hmac<Sha512>>(msg, secret),
    }
}

/// A generic method to HMAC a message using the given type
///
/// This is mainly a private method made for added convenience and code
/// readability to reduce the duplicate code with different
/// underlying digests
///
/// # Panics
/// The method will panic if the provided secret is invalid and a hash
/// cannot be generated

fn hash_internal<D: Mac>(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut hmac = <D>::new_from_slice(secret).expect("Failed to initialize HMAC");
    hmac.update(msg);
    hmac.finalize().into_bytes()[..].into()
}
