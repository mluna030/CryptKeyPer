use std::convert::TryInto;
use zeroize::ZeroizeOnDrop;

use crate::hash_function::hash_function::Sha256HashFunction;
use crate::xmss::address::XmssAddress;
use crate::errors::{CryptKeyperError, Result};

/// WOTS+ parameters
const WOTS_W: u32 = 16; // Winternitz parameter (4, 16, or 256)
const WOTS_LOG_W: u32 = 4; // log2(WOTS_W)
const WOTS_LEN1: usize = 64; // ceil(256 / log2(w)) for SHA-256
const WOTS_LEN2: usize = 3;  // floor(log2(len1 * (w-1)) / log2(w)) + 1
const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2; // Total length

/// WOTS+ One-Time Signature implementation following RFC 8391
#[derive(Clone, ZeroizeOnDrop)]
pub struct WotsPlus {
    #[zeroize(skip)]
    pub public_key: Vec<[u8; 32]>,
    private_key: Vec<[u8; 32]>,
    pub_seed: [u8; 32],
}

impl WotsPlus {
    /// Generate WOTS+ key pair from private seed and public seed
    pub fn keygen(private_seed: &[u8; 32], pub_seed: &[u8; 32], address: &XmssAddress) -> Result<Self> {
        let mut private_key = Vec::with_capacity(WOTS_LEN);
        let mut public_key = Vec::with_capacity(WOTS_LEN);
        
        let mut addr = *address;
        addr.set_key_and_mask(0);
        
        // Generate private key chains
        for i in 0..WOTS_LEN {
            addr.set_chain_address(i as u32);
            addr.set_hash_address(0);
            
            let sk_i = Self::prf(private_seed, &addr.to_bytes())?;
            private_key.push(sk_i);
            
            // Generate corresponding public key
            addr.set_hash_address(0);
            let pk_i = Self::chain(sk_i, 0, WOTS_W - 1, pub_seed, &addr)?;
            public_key.push(pk_i);
        }
        
        Ok(WotsPlus {
            private_key,
            public_key,
            pub_seed: *pub_seed,
        })
    }

    /// PRF function for key generation
    fn prf(key: &[u8; 32], input: &[u8; 32]) -> Result<[u8; 32]> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(key);
        data.extend_from_slice(input);
        
        let hash = Sha256HashFunction::hash(&data);
        hash.try_into()
            .map_err(|_| CryptKeyperError::HashError("PRF hash size mismatch".to_string()))
    }
    
    /// Hash function with bitmask for WOTS+ chaining
    fn hash_f(input: &[u8; 32], pub_seed: &[u8; 32], address: &XmssAddress) -> Result<[u8; 32]> {
        let mut addr = *address;
        addr.set_key_and_mask(0);
        let key = Self::prf(pub_seed, &addr.to_bytes())?;
        
        addr.set_key_and_mask(1);
        let bitmask = Self::prf(pub_seed, &addr.to_bytes())?;
        
        let mut masked_input = [0u8; 32];
        for i in 0..32 {
            masked_input[i] = input[i] ^ bitmask[i];
        }
        
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&key);
        data.extend_from_slice(&masked_input);
        
        let hash = Sha256HashFunction::hash(&data);
        hash.try_into()
            .map_err(|_| CryptKeyperError::HashError("Hash function size mismatch".to_string()))
    }
    
    /// Chain function for WOTS+ signatures
    pub fn chain(mut x: [u8; 32], start: u32, steps: u32, pub_seed: &[u8; 32], address: &XmssAddress) -> Result<[u8; 32]> {
        if start + steps > WOTS_W {
            return Err(CryptKeyperError::InvalidParameter("Invalid chain parameters".to_string()));
        }
        
        let mut addr = *address;
        for i in start..(start + steps) {
            addr.set_hash_address(i);
            x = Self::hash_f(&x, pub_seed, &addr)?;
        }
        
        Ok(x)
    }

    /// Convert message to base-w representation with checksum
    pub fn base_w(msg: &[u8; 32]) -> Vec<u32> {
        let mut result = Vec::with_capacity(WOTS_LEN);
        let mut csum = 0u32;
        
        // Convert message to base-w
        for byte in msg {
            let mut b = *byte;
            for _ in 0..(8 / WOTS_LOG_W) {
                let digit = (b & ((1 << WOTS_LOG_W) - 1)) as u32;
                result.push(digit);
                csum += WOTS_W - 1 - digit;
                b >>= WOTS_LOG_W;
            }
        }
        
        // Add checksum
        let csum_bytes = (csum << (8 - ((WOTS_LEN2 * WOTS_LOG_W as usize) % 8))).to_be_bytes();
        let csum_len = (WOTS_LEN2 * WOTS_LOG_W as usize + 7) / 8;
        
        for i in 0..csum_len {
            let mut b = csum_bytes[i + (4 - csum_len)];
            for _ in 0..(8 / WOTS_LOG_W) {
                if result.len() >= WOTS_LEN {
                    break;
                }
                let digit = (b & ((1 << WOTS_LOG_W) - 1)) as u32;
                result.push(digit);
                b >>= WOTS_LOG_W;
            }
        }
        
        result.truncate(WOTS_LEN);
        result
    }
    
    /// Sign a message with WOTS+
    pub fn sign(&self, message: &[u8; 32], pub_seed: &[u8; 32], address: &XmssAddress) -> Result<Vec<[u8; 32]>> {
        let msg_base_w = Self::base_w(message);
        let mut signature = Vec::with_capacity(WOTS_LEN);
        
        let mut addr = *address;
        
        for (i, &digit) in msg_base_w.iter().enumerate() {
            addr.set_chain_address(i as u32);
            addr.set_hash_address(0);
            
            let sig_i = Self::chain(self.private_key[i], 0, digit, pub_seed, &addr)?;
            signature.push(sig_i);
        }
        
        Ok(signature)
    }
    

    /// Verify a WOTS+ signature
    pub fn verify(message: &[u8; 32], signature: &[[u8; 32]], pub_key: &[[u8; 32]], pub_seed: &[u8; 32], address: &XmssAddress) -> Result<bool> {
        if signature.len() != WOTS_LEN || pub_key.len() != WOTS_LEN {
            return Err(CryptKeyperError::InvalidSignatureLength {
                expected: WOTS_LEN,
                actual: signature.len(),
            });
        }
        
        let msg_base_w = Self::base_w(message);
        let mut addr = *address;
        
        for (i, (&digit, &sig_i)) in msg_base_w.iter().zip(signature.iter()).enumerate() {
            addr.set_chain_address(i as u32);
            addr.set_hash_address(digit);
            
            let pk_from_sig = Self::chain(sig_i, digit, WOTS_W - 1 - digit, pub_seed, &addr)?;
            
            if pk_from_sig != pub_key[i] {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get the public key
    pub fn public_key(&self) -> &[[u8; 32]] {
        &self.public_key
    }
}
