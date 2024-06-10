use sha2::{sha256, Digest};
pub struct sha256HashFunction;

impl sha256HashFunction{
    pub fn Hash(data: &[u8]) -> Vec<u8>{
        let mut hasher = sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    user super::*;

    #[test]
    fn TestHash() {
        let data = b"hello world";
        let hash = sha256HashFunction::Hash(data);
        assert_eq!(hash.len(), 32);
    }
}