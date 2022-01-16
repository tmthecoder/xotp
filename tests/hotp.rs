use xotp::hotp::HOTP;

static SECRET_UTF8: &str = "12345678901234567890";
static SECRET_BYTES: &[u8] = SECRET_UTF8.as_bytes();
static SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// Generic test method to get the HOTP code with
/// the Secret Key as a byte array
fn run_rfc_test_bytes(count: u64) -> u32 {
    let hotp = HOTP::new(SECRET_BYTES);
    hotp.get_otp(count, 6)
}

/// Generic test method to get the HOTP code with
/// the Secret Key as a string literal
fn run_rfc_test_utf8(count: u64) -> u32 {
    let hotp = HOTP::from_utf8(SECRET_UTF8);
    hotp.get_otp(count, 6)
}

/// Generic test method to get the HOTP code with
/// the Secret Key as a base32-encoded string
fn run_rfc_test_base32(count: u64) -> u32 {
    let hotp = HOTP::from_base32(SECRET_BASE32);
    hotp.get_otp(count, 6)
}

// All RFC4226 Test Cases (All SHA1)

// Tests 1-4 run with SECRET_BYTES
#[test]
fn rfc_test_case_1() {
    assert_eq!(run_rfc_test_bytes(0), 755224)
}

#[test]
fn rfc_test_case_2() {
    assert_eq!(run_rfc_test_bytes(1), 287082)
}

#[test]
fn rfc_test_case_3() {
    assert_eq!(run_rfc_test_bytes(2), 359152)
}

#[test]
fn rfc_test_case_4() {
    assert_eq!(run_rfc_test_bytes(3), 969429)
}

// Tests 5-7 run with SECRET_UTF8
#[test]
fn rfc_test_case_5() {
    assert_eq!(run_rfc_test_utf8(4), 338314)
}

#[test]
fn rfc_test_case_6() {
    assert_eq!(run_rfc_test_utf8(5), 254676)
}

#[test]
fn rfc_test_case_7() {
    assert_eq!(run_rfc_test_utf8(6), 287922)
}

// Tests 8-10 run with SECRET_BASE32
#[test]
fn rfc_test_case_8() {
    assert_eq!(run_rfc_test_base32(7), 162583)
}

#[test]
fn rfc_test_case_9() {
    assert_eq!(run_rfc_test_base32(8), 399871)
}

#[test]
fn rfc_test_case_10() {
    assert_eq!(run_rfc_test_base32(9), 520489)
}
