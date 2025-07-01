use std::sync::Arc;
use parking_lot::RwLock;
use lru::LruCache;
use subtle::{Choice, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

use crate::hash_traits::HashFunction;
use crate::parameters::{WotsParameters, XmssParameterSet};
use crate::xmss::address::XmssAddress;
use crate::errors::{CryptKeyperError, Result};

/// Optimized WOTS+ implementation with lazy key generation and caching
#[derive(Clone)]
pub struct WotsPlusOptimized {
    params: WotsParameters,
    hash_function: Arc<dyn HashFunction>,
    private_seed: Arc<[u8; 32]>,
    pub_seed: Arc<[u8; 32]>,
    address: XmssAddress,
    
    // Cache for generated keys (thread-safe)
    key_cache: Arc<RwLock<LruCache<u32, CachedWotsKey>>>,
}

/// Cached WOTS+ key with both private and public components
#[derive(Clone, ZeroizeOnDrop)]
struct CachedWotsKey {
    #[zeroize(skip)]
    public_key: Vec<Vec<u8>>,
    private_key: Vec<Vec<u8>>,
}

impl WotsPlusOptimized {
    /// Create new WOTS+ instance with lazy key generation
    pub fn new(
        parameter_set: XmssParameterSet,
        private_seed: [u8; 32],
        pub_seed: [u8; 32],
        address: XmssAddress,
    ) -> Self {
        let params = parameter_set.wots_params();
        let hash_function = parameter_set.create_hash_function();
        
        // Cache size based on expected usage patterns
        let cache_size = std::cmp::min(1000, params.len * 2);
        
        Self {
            params,
            hash_function: Arc::new(hash_function),
            private_seed: Arc::new(private_seed),
            pub_seed: Arc::new(pub_seed),
            address,
            key_cache: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::new(1000).unwrap())
            ))),
        }
    }
    
    /// Generate a single WOTS+ chain lazily
    fn generate_chain_lazy(&self, chain_index: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        // Check cache first
        {
            let cache = self.key_cache.read();
            if let Some(cached_key) = cache.peek(&chain_index) {
                return Ok((
                    cached_key.private_key[chain_index as usize].clone(),
                    cached_key.public_key[chain_index as usize].clone(),
                ));
            }
        }
        
        // Generate chain if not in cache
        let mut addr = self.address;
        addr.set_chain_address(chain_index);
        addr.set_hash_address(0);
        
        // Generate private key for this chain
        let private_key = self.prf(self.private_seed.as_ref(), &addr.to_bytes())?;
        
        // Generate public key by chaining
        let public_key = self.chain(
            private_key.clone(),
            0,
            self.params.w - 1,
            &addr,
        )?;
        
        Ok((private_key, public_key))
    }
    
    /// PRF function for key generation
    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        self.hash_function.prf(key, input)
    }
    
    /// Chain function for WOTS+ signatures with constant-time operations
    fn chain(&self, mut input: Vec<u8>, start: u32, steps: u32, address: &XmssAddress) -> Result<Vec<u8>> {
        if start + steps > self.params.w {
            return Err(CryptKeyperError::InvalidParameter(
                "Chain parameters exceed Winternitz parameter".to_string()
            ));
        }
        
        let mut addr = *address;
        
        for i in start..(start + steps) {
            addr.set_hash_address(i);
            
            // Generate key and bitmask for this iteration
            addr.set_key_and_mask(0);
            let key = self.prf(self.pub_seed.as_ref(), &addr.to_bytes())?;
            
            addr.set_key_and_mask(1);
            let bitmask = self.prf(self.pub_seed.as_ref(), &addr.to_bytes())?;
            
            // Apply bitmask
            let mut masked_input = input.clone();
            for (byte, &mask_byte) in masked_input.iter_mut().zip(bitmask.iter()) {
                *byte ^= mask_byte;
            }
            
            // Hash: key || masked_input
            let mut hash_input = Vec::with_capacity(key.len() + masked_input.len());
            hash_input.extend_from_slice(&key);
            hash_input.extend_from_slice(&masked_input);
            
            input = self.hash_function.hash(&hash_input);
        }
        
        Ok(input)
    }
    
    /// Generate full WOTS+ key pair (all chains)
    pub fn generate_full_keypair(&self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        let mut private_keys = Vec::with_capacity(self.params.len);
        let mut public_keys = Vec::with_capacity(self.params.len);
        
        // Use parallel processing for key generation if enabled
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            
            let chain_results: Result<Vec<_>> = (0..self.params.len)
                .into_par_iter()
                .map(|i| self.generate_chain_lazy(i as u32))
                .collect();
            
            let chains = chain_results?;
            for (private_key, public_key) in chains {
                private_keys.push(private_key);
                public_keys.push(public_key);
            }
        }
        
        #[cfg(not(feature = "parallel"))]
        {
            for i in 0..self.params.len {
                let (private_key, public_key) = self.generate_chain_lazy(i as u32)?;
                private_keys.push(private_key);
                public_keys.push(public_key);
            }
        }
        
        // Cache the generated keys
        let cached_key = CachedWotsKey {
            private_key: private_keys.clone(),
            public_key: public_keys.clone(),
        };
        
        {
            let mut cache = self.key_cache.write();
            for i in 0..self.params.len {
                cache.put(i as u32, cached_key.clone());
            }
        }
        
        Ok((private_keys, public_keys))
    }
    
    /// Sign a message with WOTS+
    pub fn sign(&self, message: &[u8]) -> Result<Vec<Vec<u8>>> {
        if message.len() != self.hash_function.output_size() {
            return Err(CryptKeyperError::InvalidMessageLength {
                expected: self.hash_function.output_size(),
                actual: message.len(),
            });
        }
        
        // Convert message to base-w with checksum
        let base_w_msg = self.params.message_to_base_w_with_checksum(message);
        
        if base_w_msg.len() != self.params.len {
            return Err(CryptKeyperError::InvalidParameter(
                "Base-w message length mismatch".to_string()
            ));
        }
        
        let mut signature = Vec::with_capacity(self.params.len);
        
        // Generate signature components
        for (i, &steps) in base_w_msg.iter().enumerate() {
            let (private_key, _) = self.generate_chain_lazy(i as u32)?;
            
            let mut addr = self.address;
            addr.set_chain_address(i as u32);
            addr.set_hash_address(0);
            
            let sig_component = self.chain(private_key, 0, steps, &addr)?;
            signature.push(sig_component);
        }
        
        Ok(signature)
    }
    
    /// Verify a WOTS+ signature with constant-time comparison
    pub fn verify(&self, message: &[u8], signature: &[Vec<u8>]) -> Result<bool> {
        if message.len() != self.hash_function.output_size() {
            return Err(CryptKeyperError::InvalidMessageLength {
                expected: self.hash_function.output_size(),
                actual: message.len(),
            });
        }
        
        if signature.len() != self.params.len {
            return Err(CryptKeyperError::InvalidSignatureLength {
                expected: self.params.len,
                actual: signature.len(),
            });
        }
        
        // Convert message to base-w with checksum
        let base_w_msg = self.params.message_to_base_w_with_checksum(message);
        
        // Generate public key from signature and compare
        let (_, expected_public_key) = self.generate_full_keypair()?;
        
        let mut verification_result = Choice::from(1u8); // Start with true
        
        for (i, (&steps, sig_component)) in base_w_msg.iter().zip(signature.iter()).enumerate() {
            let mut addr = self.address;
            addr.set_chain_address(i as u32);
            addr.set_hash_address(steps);
            
            // Chain from signature to public key
            let remaining_steps = self.params.w - 1 - steps;
            let computed_public_key = self.chain(
                sig_component.clone(),
                steps,
                remaining_steps,
                &addr,
            )?;
            
            // Constant-time comparison
            let keys_match = computed_public_key.ct_eq(&expected_public_key[i]);
            verification_result &= keys_match;
        }
        
        Ok(verification_result.into())
    }
    
    /// Derive public key from signature
    pub fn public_key_from_signature(&self, message: &[u8], signature: &[Vec<u8>]) -> Result<Vec<u8>> {
        if message.len() != self.hash_function.output_size() {
            return Err(CryptKeyperError::InvalidMessageLength {
                expected: self.hash_function.output_size(),
                actual: message.len(),
            });
        }
        
        let base_w_msg = self.params.message_to_base_w_with_checksum(message);
        let mut public_key_elements = Vec::new();
        
        for (i, (&steps, sig_component)) in base_w_msg.iter().zip(signature.iter()).enumerate() {
            let mut addr = self.address;
            addr.set_chain_address(i as u32);
            addr.set_hash_address(steps);
            
            // Chain from signature to public key element
            let remaining_steps = self.params.w - 1 - steps;
            let pk_element = self.chain(
                sig_component.clone(),
                steps,
                remaining_steps,
                &addr,
            )?;
            
            public_key_elements.extend_from_slice(&pk_element);
        }
        
        Ok(public_key_elements)
    }
    
    /// Get the public key for this WOTS+ instance
    pub fn public_key(&self) -> Result<Vec<Vec<u8>>> {
        let (_, public_keys) = self.generate_full_keypair()?;
        Ok(public_keys)
    }
    
    /// Clear the key cache (useful for memory management)
    pub fn clear_cache(&self) {
        let mut cache = self.key_cache.write();
        cache.clear();
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.key_cache.read();
        (cache.len(), cache.cap().try_into().unwrap_or(0))
    }
}

impl std::fmt::Debug for WotsPlusOptimized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WotsPlusOptimized")
            .field("params", &self.params)
            .field("hash_function", &self.hash_function.name())
            .field("address", &self.address)
            .field("cache_stats", &self.cache_stats())
            .finish()
    }
}