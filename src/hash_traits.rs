use crate::errors::{CryptKeyperError, Result};

/// Generic hash function trait for XMSS
pub trait HashFunction: Clone + Send + Sync {
    const OUTPUT_SIZE: usize;
    const NAME: &'static str;
    
    /// Hash arbitrary length input
    fn hash(&self, data: &[u8]) -> Vec<u8>;
    
    /// PRF function for key generation
    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>>;
    
    /// Hash function with bitmask (for XMSS internal nodes)
    fn hash_with_bitmask(&self, key: &[u8], left: &[u8], right: &[u8], bitmask_seed: &[u8]) -> Result<Vec<u8>>;
}

/// SHA-256 hash function implementation
#[derive(Clone)]
pub struct Sha256HashFunction;

impl HashFunction for Sha256HashFunction {
    const OUTPUT_SIZE: usize = 32;
    const NAME: &'static str = "SHA-256";
    
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(key.len() + input.len());
        data.extend_from_slice(key);
        data.extend_from_slice(input);
        Ok(self.hash(&data))
    }
    
    fn hash_with_bitmask(&self, key: &[u8], left: &[u8], right: &[u8], bitmask_seed: &[u8]) -> Result<Vec<u8>> {
        // Generate bitmasks
        let bitmask_left = self.prf(bitmask_seed, &[1u8])?;
        let bitmask_right = self.prf(bitmask_seed, &[2u8])?;
        
        if bitmask_left.len() < left.len() || bitmask_right.len() < right.len() {
            return Err(CryptKeyperError::HashError("Insufficient bitmask length".to_string()));
        }
        
        // Apply bitmasks
        let mut masked_left = left.to_vec();
        let mut masked_right = right.to_vec();
        
        for i in 0..left.len() {
            masked_left[i] ^= bitmask_left[i];
        }
        for i in 0..right.len() {
            masked_right[i] ^= bitmask_right[i];
        }
        
        // Hash: key || masked_left || masked_right
        let mut data = Vec::with_capacity(key.len() + masked_left.len() + masked_right.len());
        data.extend_from_slice(key);
        data.extend_from_slice(&masked_left);
        data.extend_from_slice(&masked_right);
        
        Ok(self.hash(&data))
    }
}

/// SHA-512 hash function implementation
#[derive(Clone)]
pub struct Sha512HashFunction;

impl HashFunction for Sha512HashFunction {
    const OUTPUT_SIZE: usize = 64;
    const NAME: &'static str = "SHA-512";
    
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha2::{Sha512, Digest};
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(key.len() + input.len());
        data.extend_from_slice(key);
        data.extend_from_slice(input);
        Ok(self.hash(&data))
    }
    
    fn hash_with_bitmask(&self, key: &[u8], left: &[u8], right: &[u8], bitmask_seed: &[u8]) -> Result<Vec<u8>> {
        let bitmask_left = self.prf(bitmask_seed, &[1u8])?;
        let bitmask_right = self.prf(bitmask_seed, &[2u8])?;
        
        if bitmask_left.len() < left.len() || bitmask_right.len() < right.len() {
            return Err(CryptKeyperError::HashError("Insufficient bitmask length".to_string()));
        }
        
        let mut masked_left = left.to_vec();
        let mut masked_right = right.to_vec();
        
        for i in 0..left.len() {
            masked_left[i] ^= bitmask_left[i];
        }
        for i in 0..right.len() {
            masked_right[i] ^= bitmask_right[i];
        }
        
        let mut data = Vec::with_capacity(key.len() + masked_left.len() + masked_right.len());
        data.extend_from_slice(key);
        data.extend_from_slice(&masked_left);
        data.extend_from_slice(&masked_right);
        
        Ok(self.hash(&data))
    }
}

/// SHAKE128 hash function implementation
#[derive(Clone)]
pub struct Shake128HashFunction;

impl HashFunction for Shake128HashFunction {
    const OUTPUT_SIZE: usize = 32; // Can be variable, but we use 32 for consistency
    const NAME: &'static str = "SHAKE128";
    
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
        let mut hasher = Shake128::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; Self::OUTPUT_SIZE];
        reader.read(&mut output);
        output
    }
    
    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(key.len() + input.len());
        data.extend_from_slice(key);
        data.extend_from_slice(input);
        Ok(self.hash(&data))
    }
    
    fn hash_with_bitmask(&self, key: &[u8], left: &[u8], right: &[u8], bitmask_seed: &[u8]) -> Result<Vec<u8>> {
        let bitmask_left = self.prf(bitmask_seed, &[1u8])?;
        let bitmask_right = self.prf(bitmask_seed, &[2u8])?;
        
        if bitmask_left.len() < left.len() || bitmask_right.len() < right.len() {
            return Err(CryptKeyperError::HashError("Insufficient bitmask length".to_string()));
        }
        
        let mut masked_left = left.to_vec();
        let mut masked_right = right.to_vec();
        
        for i in 0..left.len() {
            masked_left[i] ^= bitmask_left[i];
        }
        for i in 0..right.len() {
            masked_right[i] ^= bitmask_right[i];
        }
        
        let mut data = Vec::with_capacity(key.len() + masked_left.len() + masked_right.len());
        data.extend_from_slice(key);
        data.extend_from_slice(&masked_left);
        data.extend_from_slice(&masked_right);
        
        Ok(self.hash(&data))
    }
}