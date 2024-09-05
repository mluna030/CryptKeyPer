use std::convert::TryInto;

use crate::hash_function::hash_function::Sha256HashFunction;
use crate::drbg::drbg::HmacDrbg;
use hex::{encode, decode};

pub struct Wots 
{
    pub private_key: Vec<[u8; 32]>,
    pub public_key: Vec<[u8; 32]>,
    w: usize,
}

impl Wots 
{
    pub fn new(seed: &[u8], w: usize) -> Self {
        let mut private_key = Vec::new();
        let mut public_key = Vec::new();

        let mut _drbg = HmacDrbg::new(seed, None);
        for i in 0..w {
            // Combine seed and `i`, hash the result, and convert to `[u8; 32]`
            let mut key_part: [u8; 32] = Sha256HashFunction::hash(&[seed, &[i as u8]].concat())
                .try_into()
                .expect("Hash output size mismatch");

            private_key.push(key_part);

            // Iteratively hash `key_part` (repeated `2^w` times)
            for _ in 0..(1 << w) {
                key_part = Sha256HashFunction::hash(&key_part)
                    .try_into()
                    .expect("Hash output size mismatch");
            }

            public_key.push(key_part);
        }

        Wots {
            private_key,
            public_key,
            w,
        }
    }

    fn chain_fn(&self, x: &[u8], steps: usize) -> [u8; 32] 
    {
        let mut result = x.to_vec();
        for _ in 0..steps 
        {
            result = Sha256HashFunction::hash(&result);
        }
        result.try_into().expect("Hash output size mismatch")
    }

    fn chain_fn_with_r(&self, x: &[u8], r: &[u8], steps: usize) -> Vec<u8> 
    {
        let mut result = x.to_vec();
        for _ in 0..steps 
        {
            result = Sha256HashFunction::hash_bytes(&[&result, r].concat());
        }
        result
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<[u8; 32]>, String> 
    {
        if message.len() != self.w 
        {
            return Err("Invalid message length".to_string());
        }

        let mut signature = Vec::new();

        for (i, &m) in message.iter().enumerate() 
        {
            let key_part = self.chain_fn(&self.private_key[i], m as usize);
            signature.push(key_part);
        }

        Ok(signature)
    }
    

    pub fn verify(&self, message: &[u8], signature: &[Vec<u8>]) -> Result<bool, String> 
    {
        if message.len() != self.w || signature.len() != self.w 
        {
            return Err("Invalid signature or message length".to_string());
        }

        for (i, sig_part) in signature.iter().enumerate() 
        {
            let expected_public_key = self.chain_fn(sig_part, (1 << self.w) - message[i] as usize);
            if expected_public_key != self.public_key[i] 
            {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
