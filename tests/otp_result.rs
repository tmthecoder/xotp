use xotp::otp_result::OTPResult;

// Tests whether a code with less than 6 digits adds on leading zeroes
#[test]
fn test_padding_needed() {
    let result = OTPResult::new(6, 1234);
    assert_eq!("001234", result.as_string())
}

// Tests whether the formatter will leave the code string as-is
#[test]
fn test_padding_not_needed() {
    let result = OTPResult::new(6, 123456);
    assert_eq!("123456", result.as_string())
}