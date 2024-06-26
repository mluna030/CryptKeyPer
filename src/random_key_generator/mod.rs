use rand::rngs::OsRng;
use rand::RngCore;

pub struct OsRandomKeyGenerator;

impl OsRandomKeyGenerator{
    pub fn GenerateKey(size: usize) -> Vect<u8> {
        let mut key = vec![0u8; size];
        OsRng.fill_bytes(&mut key);
        key
    }
    pub fn generate_hex_key(size: usize) -> String {
        encode(OsRandomKeyGenerator::generate_key(size))
    }
}

#[cfg(test)]
mod tests {
    user super::*;

    #[test]
    fn TestGenerateKey(){
        let key = OsRandomKeyGenerator::GenerateKey(32);
        assert_eq!(key.len(), 32);
    }
}