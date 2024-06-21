use sha2::{Sha256, Digest};

pub struct Sha256HashFunction;

impl Sha256HashFunction {
    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn hash_hex(data: &[u8]) -> String {
        let hash = Sha256HashFunction::hash(data);
        hex::encode(hash)
    }

    pub fn hash_bytes(data: &[u8]) -> Vec<u8> {
        Sha256HashFunction::hash(data)
    }
}
