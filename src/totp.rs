use crate::util::{get_code, hash_generic, MacDigest};

pub struct TOTP {
    secret: Vec<u8>,
    mac_digest: MacDigest
}

impl TOTP {
    pub fn new(secret: &[u8]) -> Self {
        TOTP::new_with_digest(secret, MacDigest::SHA1)
    }

    pub fn new_with_digest(secret: &[u8], mac_digest: MacDigest) -> Self {
        TOTP {
            secret: secret.to_vec(),
            mac_digest
        }
    }

    pub fn from_utf8(secret: &str) -> Self {
       TOTP::new(secret.as_bytes())
    }

    pub fn from_utf8_with_digest(secret: &str, mac_digest: MacDigest) -> Self {
        TOTP::new_with_digest(secret.as_bytes(), mac_digest)
    }
}

impl TOTP {
    pub fn get_otp(&self, time: u64, digits: u32) -> u32 {
       self.get_otp_with_custom(time, 30, 0, digits)
    }

    pub fn get_otp_with_custom(&self, time: u64, time_step: u64, time_start: u64, digits: u32) -> u32 {
        let time_count = (time - time_start) / time_step;

        let hash = hash_generic(&time_count.to_be_bytes(), &self.secret, &self.mac_digest);
        let offset = (hash[hash.len()-1] & 0xf) as usize;
        let bytes: [u8; 4] = hash[offset..offset + 4].try_into().expect("Failed byte get");

        get_code(bytes, digits)
    }
}

#[cfg(test)]
mod tests {
    use crate::util::MacDigest;
    use crate::totp::TOTP;

    static SECRET_BYTES: &[u8] = "12345678901234567890".as_bytes();
    static SECRET_STRING: &'static str = "12345678901234567890";

    fn run_rfc_test(time: u64) -> u32 {
        let totp = TOTP::new(SECRET_BYTES);
        totp.get_otp_with_custom(time, 30, 0, 8)
    }

    fn run_rfc_test_with_digest(time: u64, digest: MacDigest) -> u32 {
        let totp = TOTP::new_with_digest(SECRET_BYTES, digest);
        totp.get_otp(time, 8)
    }

    fn run_rfc_test_direct(time: u64) -> u32 {
        let totp = TOTP::from_utf8(SECRET_STRING);
        totp.get_otp_with_custom(time, 30, 0, 8)
    }

    fn run_rfc_test_direct_with_digest(time: u64, digest: MacDigest) -> u32 {
        let totp = TOTP::from_utf8_with_digest(SECRET_STRING, digest);
        totp.get_otp(time, 8)
    }

    // All SHA-1 Tests for TOTP from RTC6238
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

    #[test]
    fn rtc_test_4_sha1() {
        assert_eq!(run_rfc_test(1234567890), 89005924)
    }

    #[test]
    fn rtc_test_5_sha1() {
        assert_eq!(run_rfc_test(2000000000), 69279037)
    }

    #[test]
    fn rtc_test_6_sha1() {
        assert_eq!(run_rfc_test(20000000000), 65353130)
    }

    // All SHA-256 Tests for TOTP from RTC6238

    // All SHA-512 Tests for TOTP from RTC6238

}