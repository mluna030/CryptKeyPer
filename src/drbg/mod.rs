use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacDrbg {
    v: Vec<u8>,
    k: Vec<u8>,
}

impl HmacDrbg {
    pub fn new(entropy: &[u8], personalization: Option<&[u8]>) -> Self {
        let mut k = vec![0u8; 32];
        let mut v = vec![1u8; 32];

        let mut hmac = HmacSha256::new_from_slice(&k).unwrap();
        hmac.update(&v);
        hmac.update(entropy);
        if let Some(pers) = personalization {
            hmac.update(pers);
        }
        k = hmac.finalize().into_bytes().to_vec();

        let mut hmac = HmacSha256::new_from_slice(&k).unwrap();
        hmac.update(&v);
        v = hmac.finalize().into_bytes().to_vec();

        Self { v, k }
    }

    pub fn generate(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut result = Vec::new();
        while result.len() < num_bytes {
            let mut hmac = HmacSha256::new_from_slice(&self.k).unwrap();
            hmac.update(&self.v);
            self.v = hmac.finalize().into_bytes().to_vec();
            result.extend_from_slice(&self.v);
        }
        result.truncate(num_bytes);
        result
    }

    pub fn reseed(&mut self, entropy: &[u8]) {
        let mut hmac = HmacSha256::new_from_slice(&self.k).unwrap();
        hmac.update(&self.v);
        hmac.update(&[0u8]);
        hmac.update(entropy);
        self.k = hmac.finalize().into_bytes().to_vec();

        let mut hmac = HmacSha256::new_from_slice(&self.k).unwrap();
        hmac.update(&self.v);
        self.v = hmac.finalize().into_bytes().to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_generate() {
        let entropy = b"some_entropy";
        let mut drbg = HmacDrbg::new(entropy, None);
        let random_bytes = drbg.generate(32);
        assert_eq!(random_bytes.len(), 32);
    }
}
