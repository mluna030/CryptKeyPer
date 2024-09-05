use rand::rngs::OsRng;
use rand::RngCore;
use base64::encode;

pub struct OsRandomKeyGenerator;

impl OsRandomKeyGenerator {
    pub fn generate_key(size: usize) -> Vec<u8> 
    {
        let mut key = vec![0u8; size];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn generate_hex_key(size: usize) -> String 
    {
        encode(&OsRandomKeyGenerator::generate_key(size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() 
    {
        let key = OsRandomKeyGenerator::generate_key(32);
        assert_eq!(key.len(), 32);
    }
}