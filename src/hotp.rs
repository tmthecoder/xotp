// Implementation of the HOTP standard according to RFC4226 by Tejas Mehta

use base32::Alphabet;
use crate::util::{get_code, hash_generic, MacDigest};

/// A HOTP Generator
///
/// Follows the specification listed in [RFC4226]. Needs a secret on
/// initialization, with other single generation-specific items being
/// provided when [`HOTP::get_otp`] is called.
///
/// # Example
/// See the top-level README for an example of HOTP usage
///
/// In addition to the example, all other initialization methods can be
/// utilized in a similar manner.
///
/// [RFC4226]: https://datatracker.ietf.org/doc/html/rfc4226

#[derive(Debug, Clone, Hash)]
pub struct HOTP {
    /// The secret key used in the HMAC process.
    ///
    /// Often given as a Base32 key, which can be conveniently initialize using
    /// the [`HOTP::new_from_base32`] initializers
    secret: Vec<u8>,
}

/// All initializer implementations for the [`HOTP`] struct.

impl HOTP {
    /// Creates a new HOTP instance with a byte-array representation
    /// of the secret
    ///
    /// Since only SHA1 was specified in the reference implementation and
    /// RFC specification, there's no need to initialize with a digest object
    pub fn new(secret: &[u8]) -> Self {
       HOTP {
           secret: secret.to_vec()
       }
    }

    /// Creates a new HOTP instance from a utf8-encoded string secret
    ///
    /// Internally calls [`HOTP::new`] with the string's byte representation
    pub fn from_utf8(secret: &str) -> Self {
        HOTP::new(secret.as_bytes())
    }

    /// Creates a new HOTP instance from a base32-encoded string secret
    ///
    /// Internally calls [`HOTP::new`] after decoding the string
    ///
    /// # Panics
    /// This method panics if the provided string is not correctly base32
    /// encoded.
    pub fn from_base32(secret: &str) -> Self {
        let decoded = base32::decode(
            Alphabet::RFC4648 { padding: false }, secret
        ).expect("Failed to decode base32 string");
        HOTP::new(&decoded)
    }
}

/// All otp generation methods for the [`TOTP`] struct.

impl HOTP {
    /// Generates and returns the HOTP value
    ///
    /// Uses the given counter value with the specified digit count
    ///
    /// # Panics
    /// This method panics if the hash's secret is incorrectly given.
    pub fn get_otp(&self, counter: u64, digits: u32) -> u32 {

        let hash = hash_generic(&counter.to_be_bytes(), &self.secret, &MacDigest::SHA1);
        let offset = (hash[hash.len()-1] & 0xf) as usize;
        let bytes: [u8; 4] = hash[offset..offset + 4].try_into().expect("Failed byte get");

        get_code(bytes, digits)
    }

}