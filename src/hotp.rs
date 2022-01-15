// Implementation of the HOTP standard according to RFC4226 by Tejas Mehta

use crate::util::{get_code, hash_generic, MacDigest};

#[derive(Debug, Clone, Hash)]
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