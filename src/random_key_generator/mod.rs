use rand::rngs::OsRng;
use rand::RngCore;

pub struct OsRandomKeyGenerator;

impl OsRandomKeyGenerator{
    pub fn GenerateKey(size: usize) -> Vect<u8> {
        let mut key = vec![0u8; size];
        OsRng.fill_bytes(&mut key);
        key
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