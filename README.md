## xotp

[![xotp](https://github.com/tmthecoder/xotp/actions/workflows/xotp.yml/badge.svg)](https://github.com/tmthecoder/xotp/actions/workflows/xotp.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation the [HOTP] and [TOTP] Algorithms.

- HOTP was implemented in accordance with [RFC4226]
- TOTP was implemented in accordance with [RFC6238]

[RFC4226]: https://datatracker.ietf.org/doc/html/rfc4226
[RFC6238]: https://datatracker.ietf.org/doc/html/rfc6238
[HOTP]: https://en.wikipedia.org/wiki/HMAC-based_one-time_password
[TOTP]: https://en.wikipedia.org/wiki/Time-based_One-Time_Password

## Usage

To use HOTP:

```rust
use xotp::hotp::HOTP;

fn get_otp_with_hotp() {
    let secret = "secret";
    let counter = 0;
    // Get a HOTP instance with a '&str' secret
    let hotp_str = HOTP::from_utf8(secret);
    // Get an otp with the given counter and digit count
    let otp_from_str = hotp_str.get_otp(counter, 6);
    println!("The otp from hotp_str: {}", otp_from_str);
    
    // Alternatively, get a HOTP instance with a '&[u8]' secret
    let hotp_bytes = HOTP::new(secret.as_bytes());
    // Get an otp with the given counter and digit count
    let otp_from_bytes = hotp_bytes.get_otp(counter, 6);
    println!("The otp from hotp_bytes: {}", otp_from_bytes);
} 
```

To use TOTP:

```rust
use xotp::totp::TOTP;
use xotp::util::MacDigest;
// Only needed if using a non-SHA1 hash function
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn get_otp_with_totp() {
    let secret = "secret";
    let elapsed_seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Error getting time")
        .as_secs();
    // Get a TOTP instance a '&str' secret and default SHA1 Digest
    let totp_sha1_str = TOTP::from_utf8(secret);
    // Get an otp with the given counter and elapsed seconds 
    let otp_sha1 = totp_sha1_str.get_otp(elapsed_seconds, 8);
    println!("The otp from totp_sha1_str: {}", otp_sha1);

    // Alternatively get a TOTP instance with a '&[u8]' secret
    // and different digest (Sha256 or Sha512)
    let totp_sha256_bytes = TOTP::new_with_digest(
        secret.as_bytes(),
        MacDigest::SHA256
    );
    // Get an otp with the given counter, time and other custom params
    let otp_sha256 = totp_sha256_bytes.get_otp_with_custom(
        elapsed_seconds,
        30, // A 60-second time step
        0, // Start time at unix epoch
        6 // 8-digit code
    );
    println!("The otp from totp_sha256_bytes: {}", otp_sha256);
}
```

## Changelog

The changelog for this crate can be found at [CHANGELOG.md](https://github.com/tmthecoder/xotp/blob/main/CHANGELOG.md)

## Features and Bugs

Please file any featre requests or bug reports through the [issue tracker]

[issue tracker]: https://github.com/tmthecoder/xotp/issues

## Licensing

- xotp is licensed under the [MIT License]

[MIT License]: https://github.com/tmthecoder/xotp/blob/main/LICENSE
