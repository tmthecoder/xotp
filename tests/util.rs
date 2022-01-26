use xotp::util::ParseError;
use xotp::util::ParseResult;
use xotp::util::{parse_otpauth_uri, MacDigest};

// Examples
// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
// otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60

#[test]
fn test_otpauth_parse_invalid_uri() {
    let res = parse_otpauth_uri("");
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ParseError::UriParseError { .. }));
}

#[test]
fn test_otpauth_parse_invalid_scheme() {
    let res = parse_otpauth_uri(
        "auth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    );
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ParseError::WrongScheme { .. }));
}

#[test]
fn test_otpauth_parse_missing_otp_type() {
    let res = parse_otpauth_uri(
        "otpauth:///Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    );
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        ParseError::MissingOtpType { .. }
    ));
}

#[test]
fn test_otpauth_parse_invalid_otp_type() {
    let res = parse_otpauth_uri(
        "otpauth://xotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    );
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        ParseError::UnknownOtpType { .. }
    ));
}

#[test]
fn test_otpauth_parse_missing_secret() {
    let res = parse_otpauth_uri("otpauth://totp/Example:alice@google.com?issuer=Example");
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ParseError::MissingSecret { .. }));
}

#[test]
fn test_otpauth_parse_invalid_digits() {
    let res = parse_otpauth_uri(
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=0",
    );
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        ParseError::WrongDigitNumber { .. }
    ));
}

#[test]
fn test_otpauth_parse_invalid_digits_2() {
    let res = parse_otpauth_uri(
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=abc",
    );
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        ParseError::WrongDigitNumber { .. }
    ));
}

#[test]
fn test_otpauth_parse_totp_with_defaults() {
    let res = parse_otpauth_uri(
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    );
    assert!(res.is_ok());

    if let Ok(ParseResult::TOTP(totp)) = res {
        assert_eq!(totp.get_digest(), MacDigest::SHA1);
        assert_eq!(totp.get_digits(), 6);
        assert_eq!(totp.get_period(), 30);
    } else {
        panic!();
    }
}

#[test]
fn test_otpauth_parse_totp_specified() {
    let res = parse_otpauth_uri(
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
    );
    assert!(res.is_ok());

    if let Ok(ParseResult::TOTP(totp)) = res {
        assert_eq!(totp.get_digest(), MacDigest::SHA256);
        assert_eq!(totp.get_digits(), 8);
        assert_eq!(totp.get_period(), 60);
    } else {
        panic!();
    }
}

#[test]
fn test_otpauth_parse_totp_invalid_algorithm() {
    let res = parse_otpauth_uri(
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1024&digits=8&period=60",
    );
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        ParseError::UnknownAlgorithm { .. }
    ));
}

#[test]
fn test_otpauth_parse_totp_invalid_period() {
    let res = parse_otpauth_uri(
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=0",
    );
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ParseError::InvalidPeriod { .. }));
}

#[test]
fn test_otpauth_parse_totp_invalid_period_2() {
    let res = parse_otpauth_uri(
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=abc",
    );
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ParseError::InvalidPeriod { .. }));
}

#[test]
fn test_otpauth_parse_hotp_missing_counter() {
    let res = parse_otpauth_uri(
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co",
    );
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        ParseError::MissingCounter { .. }
    ));
}

#[test]
fn test_otpauth_parse_hotp_invalid_counter() {
    let res = parse_otpauth_uri(
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&counter=abc",
    );
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), ParseError::WrongCounter { .. }));
}

#[test]
fn test_otpauth_parse_hotp() {
    let res = parse_otpauth_uri(
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&counter=1234",
    );
    if let Ok(ParseResult::HOTP(hotp, counter)) = res {
        assert_eq!(hotp.get_digits(), 6);
        assert_eq!(counter, 1234);
    } else {
        panic!();
    }
}

#[test]
fn test_otpauth_parse_hotp_with_digits() {
    let res = parse_otpauth_uri(
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=8&counter=1234",
    );
    if let Ok(ParseResult::HOTP(hotp, counter)) = res {
        assert_eq!(hotp.get_digits(), 8);
        assert_eq!(counter, 1234);
    } else {
        panic!();
    }
}
