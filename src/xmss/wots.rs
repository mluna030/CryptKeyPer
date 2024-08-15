use crate::hash_function::Sha256HashFunction;
use crate::drbg::HmacDrbg;
use hex::{encode, decode};

pub struct Wots 
{
    pub private_key: Vec<[u8; 32]>,
    pub public_key: Vec<[u8; 32]>,
    w: usize,
}

impl Wots 
{
    pub fn new(seed: &[u8], w: usize) -> Self 
    {
        let mut private_key = Vec::new();
        let mut public_key = Vec::new();

        let mut drbg = HmacDrbg::new(seed, None);
        for _ in 0..w 
        {
            let mut key_part = Sha256HashFunction::hash(&[seed, &[i as u8]].concat());
            private_key.push(key_part);

            for _ in 0..(1 << w) 
            {
                key_part = Sha256HashFunction::hash(&key_part);
            }
            public_key.push(key_part);
        }

        Wots 
        {
            private_key,
            public_key,
            w,
        }
    }

    fn chain_fn(x: &[u8], steps: usize) -> [u8; 32] 
    {
        let mut result = x.to_vec();
        for _ in 0..steps 
        {
            result = Sha256HashFunction::hash(&result);
        }
        result.try_into().expect("Hash output size mismatch")
    }

    fn chain_fn_with_r(x: &[u8], r: &[u8], steps: usize) -> Vec<u8> 
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_function::Sha256HashFunction;

    #[test]
    fn test_wots_sign_verify() 
    {
        let seed = Sha256HashFunction::hash(b"test_seed");
        let w = 16;
        let wots = Wots::new(&seed, w);

        let message = b"test_message";
        let signature = wots.sign(message).expect("Signing failed");
        assert!(wots.verify(message, &signature).expect("Verification failed"));
    }

    #[test]
    fn test_invalid_message_length() 
    {
        let seed = Sha256HashFunction::hash(b"test_seed");
        let w = 16;
        let wots = Wots::new(&seed, w);

        let message = b"short";
        assert!(wots.sign(message).is_err(), "Expected signing to fail with invalid message length");
    }

    #[test]
    fn test_invalid_signature_length() 
    {
        let seed = Sha256HashFunction::hash(b"test_seed");
        let w = 16;
        let wots = Wots::new(&seed, w);

        let message = b"test_message";
        let mut signature = wots.sign(message).expect("Signing failed");

        signature.pop();
        assert!(wots.verify(message, &signature).is_err(), "Expected verification to fail with invalid signature length");
    }