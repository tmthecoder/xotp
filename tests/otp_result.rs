use xotp::otp_result::OTPResult;

#[test]
fn test_padding_needed() {
    let result = OTPResult::new(6, 1234);
    assert_eq!("001234", result.as_string())
}

#[test]
fn test_padding_not_needed() {
    let result = OTPResult::new(6, 123456);
    assert_eq!("123456", result.as_string())
}