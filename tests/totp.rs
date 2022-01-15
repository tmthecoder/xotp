use xotp::util::MacDigest;
use xotp::totp::TOTP;

// RFC6238 SHA1 Secret
static SECRET_STRING_SHA1: & str = "12345678901234567890";
static SECRET_BYTES_SHA1: &[u8] = SECRET_STRING_SHA1.as_bytes();

//RTC6238 SHA256 Secret
static SECRET_STRING_SHA256: &str = "12345678901234567890\
        123456789012";
static SECRET_BYTES_SHA256: &[u8] = SECRET_STRING_SHA256.as_bytes();

// RTC6238 SHA512 Secret
static SECRET_STRING_SHA512: &str = "12345678901234567890\
        12345678901234567890\
        12345678901234567890\
        1234";
static SECRET_BYTES_SHA512: &[u8] = SECRET_STRING_SHA512.as_bytes();

/// Generic test method to get the TOTP code with
/// the SHA1 Secret Key as a byte array
fn run_rfc_test(time: u64) -> u32 {
    let totp = TOTP::new(SECRET_BYTES_SHA1);
    totp.get_otp_with_custom(time, 30, 0, 8)
}

/// Generic test method to get the TOTP code with
/// the given digest's Secret Key as a byte array
fn run_rfc_test_with_digest(time: u64, digest: MacDigest) -> u32 {
    let secret = if let MacDigest::SHA256 = digest { SECRET_BYTES_SHA256 } else { SECRET_BYTES_SHA512 };
    let totp = TOTP::new_with_digest(secret, digest);
    totp.get_otp(time, 8)
}

/// Generic test method to get the TOTP code with
/// the SHA1 Secret Key as a string literal
fn run_rfc_test_direct(time: u64) -> u32 {
    let totp = TOTP::from_utf8(SECRET_STRING_SHA1);
    totp.get_otp_with_custom(time, 30, 0, 8)
}

/// Generic test method to get the TOTP code with
/// the given digest's  Secret Key as a string literal
fn run_rfc_test_direct_with_digest(time: u64, digest: MacDigest) -> u32 {
    let secret = if let MacDigest::SHA256 = digest { SECRET_STRING_SHA256 } else { SECRET_STRING_SHA512 };
    let totp = TOTP::from_utf8_with_digest(secret, digest);
    totp.get_otp(time, 8)
}

// All SHA-1 Tests for TOTP from RTC6238
// Tests 1-3 ran with 'SECRET_BYTES_SHA1'
#[test]
fn rtc_test_1_sha1() {
    assert_eq!(run_rfc_test(59), 94287082)
}

#[test]
fn rtc_test_2_sha1() {
    assert_eq!(run_rfc_test(1111111109), 07081804)
}

#[test]
fn rtc_test_3_sha1() {
    assert_eq!(run_rfc_test(1111111111), 14050471)
}

// Tests 4-6 ran with 'SECRET_STRING_SHA1'
#[test]
fn rtc_test_4_sha1() {
    assert_eq!(run_rfc_test_direct(1234567890), 89005924)
}

#[test]
fn rtc_test_5_sha1() {
    assert_eq!(run_rfc_test_direct(2000000000), 69279037)
}

#[test]
fn rtc_test_6_sha1() {
    assert_eq!(run_rfc_test_direct(20000000000), 65353130)
}

// All SHA-256 Tests for TOTP from RTC6238
// Tests 1-3 ran with 'SECRET_BYTES_SHA256'
#[test]
fn rtc_test_1_sha256() {
    assert_eq!(
        run_rfc_test_with_digest(59, MacDigest::SHA256),
        46119246
    )
}

#[test]
fn rtc_test_2_sha256() {
    assert_eq!(
        run_rfc_test_with_digest(1111111109, MacDigest::SHA256),
        68084774
    )
}

#[test]
fn rtc_test_3_sha256() {
    assert_eq!(
        run_rfc_test_with_digest(1111111111, MacDigest::SHA256),
        67062674
    )
}

// Tests 4-6 ran with 'SECRET_STRING_SHA256'
#[test]
fn rtc_test_4_sha256() {
    assert_eq!(
        run_rfc_test_direct_with_digest(1234567890, MacDigest::SHA256),
        91819424
    )
}

#[test]
fn rtc_test_5_sha256() {
    assert_eq!(
        run_rfc_test_direct_with_digest(2000000000, MacDigest::SHA256),
        90698825
    )
}

#[test]
fn rtc_test_6_sha256() {
    assert_eq!(
        run_rfc_test_direct_with_digest(20000000000, MacDigest::SHA256),
        77737706
    )
}

// All SHA-512 Tests for TOTP from RTC6238
// Tests 1-3 ran with 'SECRET_BYTES_SHA512'
#[test]
fn rtc_test_1_sha512() {
    assert_eq!(
        run_rfc_test_with_digest(59, MacDigest::SHA512),
        90693936
    )
}

#[test]
fn rtc_test_2_sha512() {
    assert_eq!(
        run_rfc_test_with_digest(1111111109, MacDigest::SHA512),
        25091201        )
}

#[test]
fn rtc_test_3_sha512() {
    assert_eq!(
        run_rfc_test_with_digest(1111111111, MacDigest::SHA512),
        99943326
    )
}

// Tests 4-6 ran with 'SECRET_STRING_SHA512'
#[test]
fn rtc_test_4_sha512() {
    assert_eq!(
        run_rfc_test_direct_with_digest(1234567890, MacDigest::SHA512),
        93441116
    )
}

#[test]
fn rtc_test_5_sha512() {
    assert_eq!(
        run_rfc_test_direct_with_digest(2000000000, MacDigest::SHA512),
        38618901
    )
}

#[test]
fn rtc_test_6_sha512() {
    assert_eq!(
        run_rfc_test_direct_with_digest(20000000000, MacDigest::SHA512),
        47863826
    )
}