use base32::Alphabet;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use url::Url;

use crate::hotp::HOTP;
use crate::totp::TOTP;

/// The digest to use with TOTP.
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

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", repr(C))]
pub enum MacDigest {
    SHA1,
    SHA256,
    SHA512,
}

/// A generic method to convert the [H/T]OTP byte-array into the
/// requested decimal-based code.
///
/// Needs the bytes to convert and the amount of digits the code should be.
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
/// TOTP instance's mac_digest is set otherwise.
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

/// A generic method to HMAC a message using the given type.
///
/// This is mainly a private method made for added convenience and code
/// readability to reduce the duplicate code with different
/// underlying digests.
///
/// # Panics
/// The method will panic if the provided secret is invalid and a hash
/// cannot be generated.
fn hash_internal<D: Mac>(msg: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut hmac = <D>::new_from_slice(secret).expect("Failed to initialize HMAC");
    hmac.update(msg);
    hmac.finalize().into_bytes()[..].into()
}

/// Decodes a base32 string according to RFC4648.
pub(crate) fn base32_decode(data: &str) -> Option<Vec<u8>> {
    base32::decode(Alphabet::RFC4648 { padding: false }, data)
}

/// Result of an otpauth URI parsing.
///
/// It's either a TOTP or a HOTP with its current counter.
#[derive(Debug)]
#[cfg_attr(feature = "ffi", repr(C))]
pub enum ParseResult {
    TOTP(TOTP),
    HOTP(HOTP, u64),
}

/// Different error types of the optauth URI parsing.
#[derive(Debug)]
#[cfg_attr(feature = "ffi", repr(C))]
pub enum ParseError {
    UriParseError(url::ParseError),
    WrongScheme(String),
    MissingOtpType,
    UnknownOtpType(String),
    MissingSecret,
    SecretParsingError(String),
    UnknownAlgorithm(String),
    WrongDigitNumber(String),
    MissingCounter,
    WrongCounter(String),
    InvalidPeriod(String),
}

/// Parses an otpauth URI, which is the string format of the QR codes usually given by platforms for TOTP.
/// This method is safe and shouldn't panic.
pub fn parse_otpauth_uri(uri: &str) -> Result<ParseResult, ParseError> {
    use ParseError::*;

    let parsed_uri = Url::parse(uri);
    if parsed_uri.is_err() {
        return Err(UriParseError(parsed_uri.unwrap_err()));
    }
    let parsed_uri = parsed_uri.unwrap();

    if !parsed_uri.scheme().eq("otpauth") {
        return Err(WrongScheme(String::from(parsed_uri.scheme())));
    }

    let query: HashMap<_, _> = parsed_uri.query_pairs().collect();

    let secret = match query.get("secret") {
        Some(x) => match base32_decode(x) {
            None => return Err(SecretParsingError(String::from(x.as_ref()))),
            Some(x) => x,
        },
        None => return Err(MissingSecret),
    };

    let digits = match query.get("digits") {
        Some(x) => match x.parse::<u32>() {
            Ok(i) => {
                if i == 0 {
                    return Err(WrongDigitNumber(String::from(x.as_ref())));
                } else {
                    i
                }
            }
            Err(_) => return Err(WrongDigitNumber(String::from(x.as_ref()))),
        },
        None => 6,
    };

    let type_str = match parsed_uri.host_str() {
        Some(x) => x,
        None => return Err(MissingOtpType),
    };

    if type_str.eq("totp") {
        let algo = match query.get("algorithm") {
            Some(x) => match x.as_ref() {
                "SHA1" => MacDigest::SHA1,
                "SHA256" => MacDigest::SHA256,
                "SHA512" => MacDigest::SHA512,
                _ => return Err(UnknownAlgorithm(String::from(x.as_ref()))),
            },
            None => MacDigest::SHA1,
        };

        let period = match query.get("period") {
            Some(x) => match x.parse::<u64>() {
                Ok(i) => {
                    if i == 0 {
                        return Err(InvalidPeriod(String::from(x.as_ref())));
                    } else {
                        i
                    }
                }
                Err(_) => return Err(InvalidPeriod(String::from(x.as_ref()))),
            },
            None => 30,
        };

        Ok(ParseResult::TOTP(TOTP::new(&secret, algo, digits, period)))
    } else if type_str.eq("hotp") {
        let counter = match query.get("counter") {
            Some(x) => match x.parse::<u64>() {
                Ok(x) => x,
                Err(_) => return Err(WrongCounter(String::from(x.as_ref()))),
            },
            None => return Err(MissingCounter),
        };

        Ok(ParseResult::HOTP(HOTP::new(&secret, digits), counter))
    } else {
        Err(UnknownOtpType(String::from(type_str)))
    }
}
