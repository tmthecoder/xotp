## 0.4.0
- **Breaking** Change the HOTP & TOTP OTP getter methods to return an instance of `OTPResult` instead of `u32`
  - Made in order to allow for the `as_string` convenience formatter that provides a correct length zero-padded string
  - The `u32` representation of the code can also be returned with `as_u32` if desired
- Add in `time_until_refresh` and `time_until_refresh_with_start` to provide a convenient way to get time until a refresh is needed

## 0.3.0
- Remove the "ffi" feature as it was incompatible with the structs. Passing them as an opaque pointer is a better idea.

## 0.2.0
- Support parsing an HOTP/TOTP instance from an otpauth URI (Thanks to [@orion78fr](https://github.com/orion78fr))
- Add in an "ffi" feature to make all structs & enums C-compatible with the `#[repr(C)]` attribute

## 0.1.0

- First Release
- Contains the HOTP & TOTP structs for their respective uses