use crate::util::{get_code, hash_generic, MacDigest};
use base32::Alphabet;

/// A TOTP generator
///
/// Follows the specification listed in [RFC6238]. Needs a secret
/// and digest algorithm on initialization, with other single
/// generation-specific items being provided when the [`TOTP::get_otp`] or
/// [`TOTP::get_otp_with_custom`] is called.
///
/// # Example
/// See the top-level README for an example of TOTP usage
///
/// In addition to the example, all other initialization methods can be
/// utilized in a similar manner.
///
/// [RFC6238]: https://datatracker.ietf.org/doc/html/rfc6238

#[derive(Debug, Clone, Hash)]
pub struct TOTP {
    /// The secret key used in the HMAC process.
    ///
    /// Often given as a Base32 key, which can be conveniently initialize using
    /// the [`TOTP::new_from_base32`] or [`TOTP::new_from_base32_with_digest`]
    /// initializers.
    secret: Vec<u8>,

    /// The digest to use in the HMAC process.
    ///
    /// Unless an initializer ending in 'with_digest' is used, this value
    /// defaults to [`MacDigest::SHA1`]
    mac_digest: MacDigest,
}

/// All initializer implementations for the [`TOTP`] struct
impl TOTP {
    /// Creates a new TOTP instance with a byte-array representation
    /// of the secret
    ///
    /// Defaults to using [`MacDigest::SHA1`] as the digest for HMAC
    /// operations.
    pub fn new(secret: &[u8]) -> Self {
        TOTP::new_with_digest(secret, MacDigest::SHA1)
    }

    /// Creates a new TOTP instance with a byte-array representation
    /// of the secret and a specific digest for HMAC operations
    ///
    /// Allows for non-SHA1 algorithms to be used with TOTP generation
    pub fn new_with_digest(secret: &[u8], mac_digest: MacDigest) -> Self {
        TOTP {
            secret: secret.to_vec(),
            mac_digest,
        }
    }

    /// Creates a new TOTP instance from a utf8-encoded string secret
    ///
    /// Like [`TOTP::new`], this method also defaults to using [`MacDigest::SHA1`]
    /// for HMAC operations.
    pub fn from_utf8(secret: &str) -> Self {
        TOTP::from_utf8_with_digest(secret, MacDigest::SHA1)
    }

    /// Creates a new TOTP instance from a utf8-encoded string secret
    ///
    /// Like [`TOTP::new_with_digest`], this method allows a digest to be specified
    /// instead of the default SHA1 being used.
    pub fn from_utf8_with_digest(secret: &str, mac_digest: MacDigest) -> Self {
        TOTP::new_with_digest(secret.as_bytes(), mac_digest)
    }

    /// Creates a new TOTP instance from a base32-encoded string secret
    ///
    /// Like [`TOTP::new`] and [`TOTP::from_utf8`] this method also defaults
    /// to using [`MacDigest::SHA1`] for HMAC operations.
    ///
    /// # Panics
    /// This method panics if the [`TOTP::from_base32_with_digest`] does,
    /// which happens when the provided string is not correctly base32 encoded.
    pub fn from_base32(secret: &str) -> Self {
        TOTP::from_base32_with_digest(secret, MacDigest::SHA1)
    }

    /// Creates a new TOTP instance from a base32-encoded string secret
    ///
    /// Like [`TOTP::new_with_digest`] and [`TOTP::from_utf8_with_digest`] this
    /// method allows a digest to be specified instead of the default SHA1.
    ///
    /// # Panics
    /// This method panics if the provided string is not correctly base32 encoded.
    pub fn from_base32_with_digest(secret: &str, mac_digest: MacDigest) -> Self {
        let decoded = base32::decode(Alphabet::RFC4648 { padding: false }, secret)
            .expect("Failed to decode base32 string");
        TOTP::new_with_digest(&decoded, mac_digest)
    }
}

/// All otp generation methods for the [`TOTP`] struct.
impl TOTP {
    /// Generates and returns the TOTP value for the time with the
    /// specified digits.
    ///
    /// The time must be specified in seconds to calculate the correct
    /// one-time password.
    ///
    /// As this method doesn't specify time steps or a starting time,
    /// the starting time is assumed to be 0 and the time step is set
    /// to the default of 30 seconds.
    ///
    /// # Panics
    /// This method panics if the called [`TOTP::get_otp_with_custom`] method
    /// does, which would happen if the hash's secret is incorrectly given.
    pub fn get_otp(&self, time: u64, digits: u32) -> u32 {
        self.get_otp_with_custom(time, 30, 0, digits)
    }

    /// Generates and returns the TOTP value for the time with a provided step,
    /// start time, and digit count
    ///
    /// Like with the [`TOTP::get_otp`] method, the time should be provided in
    /// seconds for proper calculation
    ///
    /// This method allows custom start times and time steps to be provided.
    ///
    /// # Panics
    /// This method panics if the hash's secret is incorrectly given.
    pub fn get_otp_with_custom(
        &self,
        time: u64,
        time_step: u64,
        time_start: u64,
        digits: u32,
    ) -> u32 {
        let time_count = (time - time_start) / time_step;

        let hash = hash_generic(&time_count.to_be_bytes(), &self.secret, &self.mac_digest);
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let bytes: [u8; 4] = hash[offset..offset + 4]
            .try_into()
            .expect("Failed byte get");

        get_code(bytes, digits)
    }
}
