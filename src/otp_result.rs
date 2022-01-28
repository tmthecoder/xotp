use std::time::{SystemTime, UNIX_EPOCH};

pub struct OTPResult {
    digits: u32,
    code: u32,
}

impl OTPResult {
    pub fn new(digits: u32, code: u32 ) -> Self {
        OTPResult { digits, code }
    }
}

impl OTPResult {
    pub fn get_digits(&self) -> u32 { self.digits }
}

impl OTPResult {
    pub fn as_string(&self) -> String {
        format!("{:01$}", self.code as usize, self.digits as usize)
    }

    pub fn as_u32(&self) -> u32 {
        self.code
    }
}