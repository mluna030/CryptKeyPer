use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::errors::{CryptKeyperError, Result};

type HmacSha256 = Hmac<Sha256>;

const MAX_GENERATE_BITS: usize = 7500;
const MAX_RESEED_INTERVAL: u64 = 10000;

/// HMAC-DRBG implementation following NIST SP 800-90A
#[derive(ZeroizeOnDrop)]
pub struct HmacDrbg {
    v: [u8; 32],
    k: [u8; 32],
    reseed_counter: u64,
}

impl HmacDrbg {
    /// Initialize HMAC-DRBG with entropy and optional personalization string
    pub fn new(entropy: &[u8], personalization: Option<&[u8]>) -> Result<Self> {
        if entropy.len() < 32 {
            return Err(CryptKeyperError::InvalidParameter(
                "Entropy must be at least 32 bytes".to_string()
            ));
        }
        
        let mut k = [0u8; 32];
        let mut v = [1u8; 32];

        // Initial update
        let mut seed_material = entropy.to_vec();
        if let Some(pers) = personalization {
            seed_material.extend_from_slice(pers);
        }
        
        Self::update_internal(&mut k, &mut v, Some(&seed_material))?;

        Ok(Self {
            v,
            k,
            reseed_counter: 1,
        })
    }

    /// Generate random bytes
    pub fn generate(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        if num_bytes * 8 > MAX_GENERATE_BITS {
            return Err(CryptKeyperError::DrbgError(
                format!("Cannot generate more than {} bits in a single call", MAX_GENERATE_BITS)
            ));
        }
        
        if self.reseed_counter > MAX_RESEED_INTERVAL {
            return Err(CryptKeyperError::DrbgError(
                "Reseed interval exceeded".to_string()
            ));
        }
        
        let mut result = Vec::new();
        while result.len() < num_bytes {
            let mut hmac = HmacSha256::new_from_slice(&self.k)
                .map_err(|e| CryptKeyperError::DrbgError(format!("HMAC initialization failed: {}", e)))?;
            hmac.update(&self.v);
            
            let hash_result = hmac.finalize().into_bytes();
            self.v.copy_from_slice(&hash_result[..32]);
            result.extend_from_slice(&self.v);
        }
        
        Self::update_internal(&mut self.k, &mut self.v, None)?;
        self.reseed_counter += 1;

        result.truncate(num_bytes);
        Ok(result)
    }

    /// Reseed the DRBG with new entropy
    pub fn reseed(&mut self, entropy: &[u8]) -> Result<()> {
        if entropy.len() < 32 {
            return Err(CryptKeyperError::InvalidParameter(
                "Entropy must be at least 32 bytes".to_string()
            ));
        }
        
        Self::update_internal(&mut self.k, &mut self.v, Some(entropy))?;
        self.reseed_counter = 1;
        Ok(())
    }

    /// Internal update function for HMAC-DRBG
    fn update_internal(k: &mut [u8; 32], v: &mut [u8; 32], seed_material: Option<&[u8]>) -> Result<()> {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut hmac = HmacSha256::new_from_slice(k)
            .map_err(|e| CryptKeyperError::DrbgError(format!("HMAC initialization failed: {}", e)))?;
        hmac.update(v);
        hmac.update(&[0u8]);
        if let Some(seed) = seed_material {
            hmac.update(seed);
        }
        let hash_result = hmac.finalize().into_bytes();
        k.copy_from_slice(&hash_result[..32]);

        // V = HMAC(K, V)
        let mut hmac = HmacSha256::new_from_slice(k)
            .map_err(|e| CryptKeyperError::DrbgError(format!("HMAC initialization failed: {}", e)))?;
        hmac.update(v);
        let hash_result = hmac.finalize().into_bytes();
        v.copy_from_slice(&hash_result[..32]);

        if seed_material.is_some() {
            // K = HMAC(K, V || 0x01 || provided_data)
            let mut hmac = HmacSha256::new_from_slice(k)
                .map_err(|e| CryptKeyperError::DrbgError(format!("HMAC initialization failed: {}", e)))?;
            hmac.update(v);
            hmac.update(&[1u8]);
            if let Some(seed) = seed_material {
                hmac.update(seed);
            }
            let hash_result = hmac.finalize().into_bytes();
            k.copy_from_slice(&hash_result[..32]);

            // V = HMAC(K, V)
            let mut hmac = HmacSha256::new_from_slice(k)
                .map_err(|e| CryptKeyperError::DrbgError(format!("HMAC initialization failed: {}", e)))?;
            hmac.update(v);
            let hash_result = hmac.finalize().into_bytes();
            v.copy_from_slice(&hash_result[..32]);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_generate() 
    {
        let entropy = b"some_entropy_that_is_long_enough_for_security";
        let mut drbg = HmacDrbg::new(entropy, None).expect("DRBG creation should succeed");
        let random_bytes = drbg.generate(32).expect("Generation should succeed");
        assert_eq!(random_bytes.len(), 32);
    }
}
