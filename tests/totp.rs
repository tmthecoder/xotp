use xotp::totp::TOTP;
use xotp::util::MacDigest;

// RFC6238 SHA1 Secret
static SECRET_UTF8_SHA1: &str = "12345678901234567890";
static SECRET_BYTES_SHA1: &[u8] = SECRET_UTF8_SHA1.as_bytes();
static SECRET_BASE32_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// RFC6238 SHA256 Secret
static SECRET_UTF8_SHA256: &str = "12345678901234567890\
        123456789012";
static SECRET_BYTES_SHA256: &[u8] = SECRET_UTF8_SHA256.as_bytes();
static SECRET_BASE32_SHA256: &str = "GEZDGNBVGY3TQOJQGEZ\
        DGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";

// RFC6238 SHA512 Secret
static SECRET_UTF8_SHA512: &str = "12345678901234567890\
        12345678901234567890123456789012345678901234";
static SECRET_BYTES_SHA512: &[u8] = SECRET_UTF8_SHA512.as_bytes();
static SECRET_BASE32_SHA512: &str = "GEZDGNBVGY3TQOJQGEZ\
        DGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZ\
        DGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

/// Generic test method to get the TOTP code with
/// the SHA1 Secret Key as a byte array
fn run_rfc_test_bytes(time: u64) -> u32 {
    let totp = TOTP::new(SECRET_BYTES_SHA1, MacDigest::SHA1, 8, 30);
    totp.get_otp(time).as_u32()
}

/// Generic test method to get the TOTP code with
/// the given digest's Secret Key as a byte array
fn run_rfc_test_bytes_with_digest(time: u64, digest: MacDigest) -> u32 {
    let secret = if let MacDigest::SHA256 = digest {
        SECRET_BYTES_SHA256
    } else {
        SECRET_BYTES_SHA512
    };
    let totp = TOTP::new(secret, digest, 8, 30);
    totp.get_otp(time).as_u32()
}

/// Generic test method to get the TOTP code with
/// the SHA1 Secret Key as a string literal
fn run_rfc_test_utf8(time: u64) -> u32 {
    let totp = TOTP::new_from_utf8(SECRET_UTF8_SHA1, MacDigest::SHA1, 8, 30);
    totp.get_otp(time).as_u32()
}

/// Generic test method to get the TOTP code with
/// the given digest's Secret Key as a string literal
fn run_rfc_test_utf8_with_digest(time: u64, digest: MacDigest) -> u32 {
    let secret = if let MacDigest::SHA256 = digest {
        SECRET_UTF8_SHA256
    } else {
        SECRET_UTF8_SHA512
    };
    let totp = TOTP::new_from_utf8(secret, digest, 8, 30);
    totp.get_otp(time).as_u32()
}

/// Generic test method to get the TOTP code with
/// the SHA1 Secret Key as a base32-encoded string
fn run_rfc_test_base32(time: u64) -> u32 {
    let totp = TOTP::new_from_base32(SECRET_BASE32_SHA1, MacDigest::SHA1, 8, 30);
    totp.get_otp(time).as_u32()
}

/// Generic test method to get the TOTP code with
/// the given digest's Secret Key as a base32-encoded string
fn run_rfc_test_base32_with_digest(time: u64, digest: MacDigest) -> u32 {
    let secret = if let MacDigest::SHA256 = digest {
        SECRET_BASE32_SHA256
    } else {
        SECRET_BASE32_SHA512
    };
    let totp = TOTP::new_from_base32(secret, digest, 8, 30);
    totp.get_otp(time).as_u32()
}

// All SHA-1 Tests for TOTP from rfc6238
// Tests 1-2 ran with 'SECRET_BYTES_SHA1'
#[test]
fn rfc_test_1_sha1() {
    assert_eq!(run_rfc_test_bytes(59), 94287082)
}

#[test]
fn rfc_test_2_sha1() {
    assert_eq!(run_rfc_test_bytes(1111111109), 07081804)
}

// Tests 3-4 ran with 'SECRET_UTF8_SHA1'
#[test]
fn rfc_test_3_sha1() {
    assert_eq!(run_rfc_test_utf8(1111111111), 14050471)
}

#[test]
fn rfc_test_4_sha1() {
    assert_eq!(run_rfc_test_utf8(1234567890), 89005924)
}

// Tests 5-6 ran with 'SECRET_BASE32_SHA1'
#[test]
fn rfc_test_5_sha1() {
    assert_eq!(run_rfc_test_base32(2000000000), 69279037)
}

#[test]
fn rfc_test_6_sha1() {
    assert_eq!(run_rfc_test_base32(20000000000), 65353130)
}

// All SHA-256 Tests for TOTP from rfc6238
// Tests 1-2 ran with 'SECRET_BYTES_SHA256'
#[test]
fn rfc_test_1_sha256() {
    assert_eq!(
        run_rfc_test_bytes_with_digest(59, MacDigest::SHA256),
        46119246
    )
}

#[test]
fn rfc_test_2_sha256() {
    assert_eq!(
        run_rfc_test_bytes_with_digest(1111111109, MacDigest::SHA256),
        68084774
    )
}

// Tests 3-4 ran with 'SECRET_UTF8_SHA256'
#[test]
fn rfc_test_3_sha256() {
    assert_eq!(
        run_rfc_test_utf8_with_digest(1111111111, MacDigest::SHA256),
        67062674
    )
}

#[test]
fn rfc_test_4_sha256() {
    assert_eq!(
        run_rfc_test_utf8_with_digest(1234567890, MacDigest::SHA256),
        91819424
    )
}

// Tests 5-6 ran with 'SECRET_BASE32_SHA256'
#[test]
fn rfc_test_5_sha256() {
    assert_eq!(
        run_rfc_test_base32_with_digest(2000000000, MacDigest::SHA256),
        90698825
    )
}

#[test]
fn rfc_test_6_sha256() {
    assert_eq!(
        run_rfc_test_base32_with_digest(20000000000, MacDigest::SHA256),
        77737706
    )
}

// All SHA-512 Tests for TOTP from rfc6238
// Tests 1-2 ran with 'SECRET_BYTES_SHA512'
#[test]
fn rfc_test_1_sha512() {
    assert_eq!(
        run_rfc_test_bytes_with_digest(59, MacDigest::SHA512),
        90693936
    )
}

#[test]
fn rfc_test_2_sha512() {
    assert_eq!(
        run_rfc_test_bytes_with_digest(1111111109, MacDigest::SHA512),
        25091201
    )
}

// Tests 3-4 ran with 'SECRET_UTF8_SHA512'
#[test]
fn rfc_test_3_sha512() {
    assert_eq!(
        run_rfc_test_utf8_with_digest(1111111111, MacDigest::SHA512),
        99943326
    )
}

#[test]
fn rfc_test_4_sha512() {
    assert_eq!(
        run_rfc_test_utf8_with_digest(1234567890, MacDigest::SHA512),
        93441116
    )
}

// Tests 5-6 ran with 'SECRET_BASE32_SHA512'
#[test]
fn rfc_test_5_sha512() {
    assert_eq!(
        run_rfc_test_base32_with_digest(2000000000, MacDigest::SHA512),
        38618901
    )
}

#[test]
fn rfc_test_6_sha512() {
    assert_eq!(
        run_rfc_test_base32_with_digest(20000000000, MacDigest::SHA512),
        47863826
    )
}
