## 0.3.6
- Remove the "ffi" feature as it was incompatible with the structs. Passing them as an opaque pointer is a better idea.

## 0.2.0
- Support parsing an HOTP/TOTP instance from an otpauth URI (Thanks to [@orion78fr](https://github.com/orion78fr))
- Add in an "ffi" feature to make all structs & enums C-compatible with the `#[repr(C)]` attribute

## 0.1.0

- First Release
- Contains the HOTP & TOTP structs for their respective uses