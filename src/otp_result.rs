use std::fmt;
use std::fmt::Formatter;

/// A convenience struct to hold the result of a [`HOTP`] or [`TOTP`]
/// generation.
///
/// Contains the amount of digits the OTP should be, and the actual OTP,
/// which will be equal to or less than the digit count. Currently houses
/// a convenience [`OTPResult::as_string`] which returns a zero-padded string
/// that has a length of [`OTPResult::digits`]. Additionally, the numerical
/// representation of the code can be got with [`OTPResult::as_u32`].
///
/// Returned as a result of either [`HOTP::get_otp`], [`TOTP::get_otp`]
/// or [`TOTP::get_otp_with_custom_time_start`].
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct OTPResult {
    digits: u32,
    code: u32,
}

/// Constructors for the [`OTPResult`] struct.
impl OTPResult {
    /// Creates a new instance with the provided digit count and OTP code.
    pub fn new(digits: u32, code: u32 ) -> Self {
        OTPResult { digits, code }
    }
}

/// Getters for the [`OTPResult`] struct.
impl OTPResult {
    /// Gets the digit count given to the struct on creation.
    ///
    /// Also the count used to determine how long the formatted string will be.
    pub fn get_digits(&self) -> u32 { self.digits }
}

/// Convenience code getters for the [`OTPResult`] struct
impl OTPResult {
    /// Returns the OTP as a formatted string of length [`OTPResult.digits`].
    ///
    /// If [`OTPResult::code`] is less than [`OTPResult::digits`] long, leading zeroes
    /// will be added to the string.
    pub fn as_string(&self) -> String {
        format!("{:01$}", self.code as usize, self.digits as usize)
    }


    /// Returns the OTP as it's original numerical representation
    ///
    /// This number may not be [`OTPResult::digits`] long.
    pub fn as_u32(&self) -> u32 {
        self.code
    }
}

/// A Display implementation for the [`OTPResult`] struct
///
/// Returns the String-formatted code, which is zero-padded
/// to be [`OTPResult::digits`] long.
impl fmt::Display for OTPResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
       write!(f, "{}", self.as_string())
    }
}