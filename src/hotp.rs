// Implementation of the HOTP standard according to RFC4226 by Tejas Mehta

use crate::util::{get_code, hash_generic, MacDigest};

pub struct HOTP {
    secret: Vec<u8>,
}

impl HOTP {
    pub fn new(secret: &[u8]) -> Self {
       HOTP {
           secret: secret.to_vec()
       }
    }

    pub fn from_utf8(secret: &str) -> Self {
        HOTP::new(secret.as_bytes())
    }

}

impl HOTP {
    pub fn get_otp(&self, counter: u64, digits: u32) -> u32 {

        let hash = hash_generic(&counter.to_be_bytes(), &self.secret, &MacDigest::SHA1);
        let offset = (hash[hash.len()-1] & 0xf) as usize;
        let bytes: [u8; 4] = hash[offset..offset + 4].try_into().expect("Failed byte get");

        get_code(bytes, digits)
    }

}

#[cfg(test)]
mod tests {
    use crate::hotp::HOTP;

    static SECRET_BYTES: &[u8] = "12345678901234567890".as_bytes();
    static SECRET_STRING: &'static str = "12345678901234567890";

    fn run_rfc_test(count: u64) -> u32 {
        let hotp = HOTP::new(SECRET_BYTES);
        hotp.get_otp(count, 6)
    }

    fn run_rfc_test_direct(count: u64) -> u32 {
        let hotp = HOTP::from_utf8(SECRET_STRING);
        hotp.get_otp(count, 6)
    }

    // All RFC4226 Test Cases (All SHA1)
    //Tests 1-5 run with SECRET_BYTES, 6-10 run with SECRET_STRING
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
}