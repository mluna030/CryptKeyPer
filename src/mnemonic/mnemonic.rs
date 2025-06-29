use crate::errors::{CryptKeyperError, Result};
use crate::hash_function::hash_function::Sha256HashFunction;

/// Simple mnemonic seed handling (placeholder implementation)
/// Note: This is a basic implementation. For production use, consider using
/// established standards like BIP39 for mnemonic generation and validation.
pub struct MnemonicSeed {
    seed_bytes: Vec<u8>,
}

impl MnemonicSeed {
    /// Create a new mnemonic seed from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 16 {
            return Err(CryptKeyperError::InvalidParameter(
                "Seed must be at least 16 bytes".to_string()
            ));
        }
        
        Ok(MnemonicSeed {
            seed_bytes: bytes.to_vec(),
        })
    }
    
    /// Create a mnemonic seed from a passphrase using simple key derivation
    pub fn from_passphrase(passphrase: &str, salt: Option<&[u8]>) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(CryptKeyperError::InvalidParameter(
                "Passphrase cannot be empty".to_string()
            ));
        }
        
        let salt = salt.unwrap_or(b"XMSS_SEED_SALT");
        let mut derived_key = Vec::new();
        
        // Simple key derivation (not PBKDF2, just for demonstration)
        for i in 0u32..1000 {
            let mut input = passphrase.as_bytes().to_vec();
            input.extend_from_slice(salt);
            input.extend_from_slice(&i.to_be_bytes());
            let hash = Sha256HashFunction::hash(&input);
            if i == 999 {
                derived_key = hash;
            }
        }
        
        Self::from_bytes(&derived_key)
    }
    
    /// Get the seed as bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.seed_bytes
    }
    
    /// Get a fixed-size seed for cryptographic operations
    pub fn to_seed(&self) -> [u8; 32] {
        let hash = Sha256HashFunction::hash(&self.seed_bytes);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_from_bytes() {
        let bytes = b"this_is_a_test_seed_that_is_long_enough";
        let seed = MnemonicSeed::from_bytes(bytes).unwrap();
        assert_eq!(seed.to_bytes(), bytes);
    }

    #[test]
    fn test_mnemonic_from_passphrase() {
        let passphrase = "strong_passphrase";
        let seed = MnemonicSeed::from_passphrase(passphrase, None).unwrap();
        assert_eq!(seed.to_seed().len(), 32);
    }

    #[test]
    fn test_mnemonic_too_short() {
        let bytes = b"short";
        let result = MnemonicSeed::from_bytes(bytes);
        assert!(result.is_err());
    }
}