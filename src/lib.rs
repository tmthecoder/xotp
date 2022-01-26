//! An Rust implementation of the [HOTP] and [TOTP] algorithms
//!
//! - HOTP was implemented in accordance with [RFC4226]
//! - TOTP was implemented in accordance with [RFC6238]
//!
//! # Usage
//!
//! [HOTP](hotp::HOTP) can be used in the following way:
//!
//! ```rust
//! use xotp::hotp::HOTP;
//!
//! fn get_otp_with_hotp() {
//!     let secret = "secret";
//!     let counter = 0;
//!     // Get a HOTP instance with a '&str' secret
//!     let hotp_str = HOTP::default_from_utf8(secret);
//!     // Get an otp with the given counter
//!     let otp_from_str = hotp_str.get_otp(counter);
//!     println!("The otp from hotp_str: {}", otp_from_str);
//!
//!     // Alternatively, get a HOTP instance with a '&[u8]' secret
//!     let hotp_bytes = HOTP::new(secret.as_bytes(), 6);
//!     // Get an otp with the given counter
//!     let otp_from_bytes = hotp_bytes.get_otp(counter);
//!     println!("The otp from hotp_bytes: {}", otp_from_bytes);
//! }
//! ```
//!
//! [TOTP](totp::TOTP) can be used in the following way:
//!
//! ```rust
//! use xotp::totp::TOTP;
//! use xotp::util::MacDigest; // Only needed if using a non-SHA1 hash function
//! use std::time::{Duration, SystemTime, UNIX_EPOCH};
//!
//! fn get_otp_with_totp() {
//!     let secret = "secret";
//!     let elapsed_seconds = SystemTime::now()
//!         .duration_since(UNIX_EPOCH)
//!         .expect("Error getting time")
//!         .as_secs();
//!     // Get a TOTP instance with an '&str' secret and default SHA1 Digest
//!     let totp_sha1_str = TOTP::default_from_utf8(secret);
//!     // Get an otp with the given counter and elapsed seconds
//!     let otp_sha1 = totp_sha1_str.get_otp(elapsed_seconds);
//!     println!("The otp from totp_sha1_str: {}", otp_sha1);
//!
//!     // Alternatively get a TOTP instance with an '&[u8]' secret
//!     // and different digest (Sha256 or Sha512)
//!     let totp_sha256_bytes = TOTP::new(
//!         secret.as_bytes(),
//!         MacDigest::SHA256, // SHA256 algorithm
//!         8,  // 8 digits
//!         60  // 60-second interval
//!     );
//!     // Get an otp with the given counter, time and other custom params
//!     let otp_sha256 = totp_sha256_bytes.get_otp_with_custom_time_start(
//!         elapsed_seconds,
//!         0, // Start time at unix epoch
//!     );
//!     println!("The otp from totp_sha256_bytes: {}", otp_sha256);
//! }
//! ```
//!
//! ## Changelog
//!
//! The changelog for this crate can be found at [CHANGELOG.md](https://github.com/tmthecoder/xotp/blob/main/CHANGELOG.md)
//!
//! # Licensing
//!
//! - xotp is licensed under the [MIT License]
//!
//! [HOTP]: https://en.wikipedia.org/wiki/HMAC-based_one-time_password
//! [TOTP]: https://en.wikipedia.org/wiki/Time-based_One-Time_Password
//! [RFC4226]: https://datatracker.ietf.org/doc/html/rfc4226
//! [RFC6238]: https://datatracker.ietf.org/doc/html/rfc6238
//! [MIT License]: https://github.com/tmthecoder/xotp/blob/main/LICENSE

pub mod hotp;
pub mod totp;
pub mod util;
