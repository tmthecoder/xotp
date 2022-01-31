use crate::hotp::HOTP;
use crate::totp::TOTP;
use crate::util::parse_otpauth_uri;
use crate::util;

use wasm_bindgen::prelude::*;

// WASM-specific code (Non C-style enums aren't supported by wasm_bindgen)
// So we have to add some compatibility to the parse_otpauth_uri method

/// A tuple struct to hold an OTP Parse Result
///
/// Holds an [`Option`] of each HOTP (with counter) or TOTP parse result.
/// The value which isn't of type [`None`] is the parse result. If both
/// are [`None`] then there was an error in parsing the URI.
#[wasm_bindgen]
pub struct ParseResult(
    /// The potential HOTP result given by the parser
    Option<HOTPResult>,
    /// The potential TOTP result given by the parser
    Option<TOTP>,
);

/// Getters for the [`ParseResult`] struct
#[wasm_bindgen]
impl ParseResult {
    /// Gets the [`HOTPResult`] provided by the parser
    ///
    /// If [`None`], then the parsed URI was not a HOTP URI.
    /// If a value, then the parsed URI was HOTP and also contains the
    /// associated counter.
    #[wasm_bindgen(getter)]
    pub fn get_hotp_result(&self) -> Option<HOTPResult> {
        self.0.clone()
    }

    /// Gets the [`TOTP`] provided by the parser
    ///
    /// If [`None`], then the parsed URI was not a TOTP URI.
    /// If a value, then the parsed URI was TOTP and OTPs can be generated
    #[wasm_bindgen(getter)]
    pub fn get_totp(&self) -> Option<TOTP> {
        self.1.clone()
    }
}

/// A tuple struct to hold the HOTP result given by a parser
///
/// Holds an instance of the [`HOTP`] struct and a numeric counter
#[wasm_bindgen]
#[derive(Clone)]
pub struct HOTPResult(
    /// The HOTP instance
    HOTP,
    /// The counter needed for OTP generation
    u64
);

/// Getters for the [`HOTPResult`] struct
#[wasm_bindgen]
impl HOTPResult {
    /// Gets the [`HOTP`] instance associated with this result
    #[wasm_bindgen(getter)]
    pub fn get_hotp(&self) -> HOTP {
        self.0.clone()
    }

    /// Gets the current counter value for use with the HOTP generation
    #[wasm_bindgen(getter)]
    pub fn get_counter(&self) -> u64 {
        self.1
    }
}

/// A wasm-compatible method to parse an otpauth URI into its specific OTP
/// generator. Returns the [`ParseResult`] object, which will contain
/// one or neither of the HOTP/TOTP instances.
#[wasm_bindgen]
pub fn parse_otpauth_uri_wasm(uri: &str) -> ParseResult {
    match parse_otpauth_uri(uri) {
        Ok(util::ParseResult::HOTP(result, counter)) => ParseResult(Some(HOTPResult(result, counter)), None),
        Ok(util::ParseResult::TOTP(result)) => ParseResult(None, Some(result)),
        Err(_e) => ParseResult(None, None)
    }
}