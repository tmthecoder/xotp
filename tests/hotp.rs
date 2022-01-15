use xotp::hotp::HOTP;

static SECRET_BYTES: &[u8] = "12345678901234567890".as_bytes();
static SECRET_STRING: &'static str = "12345678901234567890";

/// Generic test method to get the HOTP code with
/// the RFC Secret Key as a byte array
fn run_rfc_test(count: u64) -> u32 {
    let hotp = HOTP::new(SECRET_BYTES);
    hotp.get_otp(count, 6)
}

/// Generic test method to get the HOTP code with
/// the RTC Secret Key as a String Literal
fn run_rfc_test_direct(count: u64) -> u32 {
    let hotp = HOTP::from_utf8(SECRET_STRING);
    hotp.get_otp(count, 6)
}

// All RFC4226 Test Cases (All SHA1)

// Tests 1-5 run with SECRET_BYTES
#[test]
fn rfc_test_case_1() {
    assert_eq!(run_rfc_test(0), 755224)
}

#[test]
fn rfc_test_case_2() {
    assert_eq!(run_rfc_test(1), 287082)
}

#[test]
fn rfc_test_case_3() {
    assert_eq!(run_rfc_test(2), 359152)
}

#[test]
fn rfc_test_case_4() {
    assert_eq!(run_rfc_test(3), 969429)
}

#[test]
fn rfc_test_case_5() {
    assert_eq!(run_rfc_test(4), 338314)
}

// Tests 6-10 run with SECRET_STRING
#[test]
fn rfc_test_case_6() {
    assert_eq!(run_rfc_test_direct(5), 254676)
}

#[test]
fn rfc_test_case_7() {
    assert_eq!(run_rfc_test_direct(6), 287922)
}

#[test]
fn rfc_test_case_8() {
    assert_eq!(run_rfc_test_direct(7), 162583)
}

#[test]
fn rfc_test_case_9() {
    assert_eq!(run_rfc_test_direct(8), 399871)
}

#[test]
fn rfc_test_case_10() {
    assert_eq!(run_rfc_test_direct(9), 520489)
}