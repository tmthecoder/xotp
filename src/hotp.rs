// Implementation of the HOTP standard according to RFC4226 by Tejas Mehta

use crate::util::{base32_decode, get_code, hash_generic, MacDigest};

/// A HOTP Generator
///
/// Follows the specification listed in [RFC4226]. Needs a secret and a number of digits on initialization.
/// The HOTP can then be generated using [`HOTP::get_otp`].
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
    /// the [`HOTP::from_base32`] constructors.
    secret: Vec<u8>,

    /// The number of digits of the code generated.
    ///
    /// This value defaults to 6 if not specified in a constructor.
    digits: u32,
}

/// All initializer implementations for the [`HOTP`] struct.
impl HOTP {
    /// Creates a new HOTP instance with a byte-array representation
    /// of the secret and the number of digits.
    ///
    /// Since only SHA1 was specified in the reference implementation and
    /// RFC specification, there's no need to initialize with a digest object.
    pub fn new(secret: &[u8], digits: u32) -> Self {
        HOTP {
            secret: secret.to_vec(),
            digits,
        }
    }

    /// Creates a new HOTP instance from an utf8-encoded string secret and the number of digits.
    pub fn new_from_utf8(secret: &str, digits: u32) -> Self {
        HOTP::new(secret.as_bytes(), digits)
    }

    /// Creates a new HOTP instance from a base32-encoded string secret and the number of digits.
    ///
    /// # Panics
    /// This method panics if the provided string is not correctly base32 encoded.
    pub fn new_from_base32(secret: &str, digits: u32) -> Self {
        let decoded = base32_decode(secret).expect("Failed to decode base32 string");
        HOTP::new(&decoded, digits)
    }

    /// Creates a new HOTP instance from a byte-array representation of the secret and
    /// a default number of 6 digits.
    pub fn default_from_secret(secret: &[u8]) -> Self {
        HOTP::new(secret, 6)
    }

    /// Creates a new HOTP instance from an utf8-encoded string secret and a default number of 6 digits.
    pub fn default_from_utf8(secret: &str) -> Self {
        HOTP::new_from_utf8(secret, 6)
    }

    /// Creates a new HOTP instance from a base32-encoded string secret and a default number of 6 digits.
    ///
    /// # Panics
    /// This method panics if the provided string is not correctly base32 encoded.
    pub fn default_from_base32(secret: &str) -> Self {
        HOTP::new_from_base32(secret, 6)
    }
}

impl HOTP {
    /// Gets the number of digits of the code.
    pub fn get_digits(&self) -> u32 {
        self.digits
    }
}

/// All otp generation methods for the [`HOTP`] struct.
impl HOTP {
    /// Generates and returns the HOTP value.
    ///
    /// Uses the given counter value.
    ///
    /// # Panics
    /// This method panics if the hash's secret is incorrectly given.
    pub fn get_otp(&self, counter: u64) -> u32 {
        let hash = hash_generic(&counter.to_be_bytes(), &self.secret, &MacDigest::SHA1);
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let bytes: [u8; 4] = hash[offset..offset + 4]
            .try_into()
            .expect("Failed byte get");

        get_code(bytes, self.digits)
    }
}
