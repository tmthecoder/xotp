use crate::util::{get_code, hash_generic, MacDigest};

#[derive(Debug, Clone, Hash)]
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