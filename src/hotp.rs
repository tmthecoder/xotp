// Implementation of the HOTP standard according to RFC4226 by Tejas Mehta

use crate::otp_shared::hash_sha1;

pub struct HOTP {
    hmac_secret: Vec<u8>,
}

impl HOTP {
    pub fn new(hmac_secret: &[u8]) -> Self {
        HOTP {
            hmac_secret: hmac_secret.to_vec()
        }
    }

    pub fn from_utf8(string: &str) -> Self {
        HOTP {
            hmac_secret: string.as_bytes().into()
        }
    }
}

impl HOTP {
    pub fn get_otp(&self, mut counter: usize, digits: u32) -> u32 {
        let msg: Vec<u8> = (0..8).rev().map(|_x| {
            let val = counter & 0xf;
            counter >>= 8;
            val as u8
        }).collect();

        let hash = hash_sha1(&msg, &self.hmac_secret);
        let offset = (hash[hash.len()-1] & 0xf) as usize;

        let code: u32 = (((hash[offset] & 0x7f) as u32) << 24)
            | (((hash[offset + 1] & 0xff) as u32) << 16)
            | (((hash[offset + 2] & 0xff) as u32) << 8)
            | (hash[offset + 3] & 0xff) as u32;

        code % (10_u32.pow(digits))
    }

}

#[cfg(test)]
mod tests {
    use crate::hotp::HOTP;

    #[test]
    fn test_otp() {
        let hotp = HOTP::new("Secret".as_bytes().into());
        let otp = hotp.get_otp(4, 6);
        println!("OTP {otp:}");
        assert!(otp.to_string().len() <= 6);
    }
}