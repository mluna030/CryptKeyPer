use crate::hash_function::Sha256HashFunction;
use crate::drbg::HmacDrbg;
use hex::{encode, decode};

pub struct Wots {
    pub private_key: Vec<String>,
    pub public_key: Vec<String>,
    w: usize,
}

impl Wots {
    pub fn new(seed: &[u8], w: usize) -> Self {
        let mut private_key = Vec::new();
        let mut public_key = Vec::new();

        let mut drbg = HmacDrbg::new(seed, None);
        for _ in 0..w {
            let sk_part = drbg.generate(32);
            let pk_part = Self::chain_fn(&sk_part, w - 1);
            private_key.push(encode(&sk_part));
            public_key.push(encode(&pk_part));
        }

        Wots {
            private_key,
            public_key,
            w,
        }
    }

    fn chain_fn(x: &[u8], steps: usize) -> Vec<u8> {
        let mut result = x.to_vec();
        for _ in 0..steps {
            result = Sha256HashFunction::hash_bytes(&result);
        }
        result
    }

    fn chain_fn_with_r(x: &[u8], r: &[u8], steps: usize) -> Vec<u8> {
        let mut result = x.to_vec();
        for _ in 0..steps {
            result = Sha256HashFunction::hash_bytes(&[&result, r].concat());
        }
        result
    }

    pub fn sign(&self, message: &[u8]) -> Vec<String> {
        let hash = Sha256HashFunction::hash_bytes(message);
        let mut signature = Vec::new();
    
        for (i, &byte) in hash.iter().enumerate() {
            if i >= self.private_key.len() {
                break;
            }
            let sk_part = decode(&self.private_key[i]).unwrap();
            let sig_part = Self::chain_fn_with_r(&sk_part, &sk_part, byte as usize);
            signature.push(encode(&sig_part));
        }
    
        signature
    }
    

    pub fn verify(&self, message: &[u8], signature: &[String]) -> bool {
        let hash = Sha256HashFunction::hash_bytes(message);
    
        for (i, &byte) in hash.iter().enumerate() {
            if i >= signature.len() || i >= self.public_key.len() {
                return false;
            }
            let sig_part = decode(&signature[i]).unwrap();
            let pk_part = Self::chain_fn_with_r(&sig_part, &sig_part, (self.w - 1) - byte as usize);
            if encode(pk_part) != self.public_key[i] {
                return false;
            }
        }
    
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wots() {
        let seed = b"some_random_seed";
        let wots = Wots::new(seed, 16);
        let message = b"hello world";
        let signature = wots.sign(message);
        assert!(wots.verify(message, &signature));
    }
}