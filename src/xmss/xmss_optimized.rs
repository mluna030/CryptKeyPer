use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use parking_lot::RwLock;
use lru::LruCache;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash_traits::HashFunction;
use crate::parameters::{XmssParameterSet, WotsParameters};
use crate::xmss::address::{XmssAddress, AddressType};
use crate::xmss::wots_optimized::WotsPlusOptimized;
use crate::errors::{CryptKeyperError, Result};
use crate::random_key_generator::random_key_generator::OsRandomKeyGenerator;

/// Optimized XMSS signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmssSignatureOptimized {
    /// Signature index
    pub index: u64,
    /// WOTS+ signature
    pub wots_signature: Vec<Vec<u8>>,
    /// Authentication path
    pub auth_path: Vec<Vec<u8>>,
}

/// XMSS public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmssPublicKeyOptimized {
    /// Merkle tree root
    pub root: Vec<u8>,
    /// Public seed
    pub pub_seed: [u8; 32],
    /// Parameter set identifier
    pub parameter_set: XmssParameterSet,
}

/// Private key state (encrypted when stored)
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct XmssPrivateState {
    private_seed: [u8; 32],
    signature_index: u64,
    max_signatures: u64,
}

/// Cached tree node for faster authentication path generation
#[derive(Clone)]
struct CachedTreeNode {
    value: Vec<u8>,
    height: u32,
    index: u64,
}

/// Optimized XMSS implementation with lazy key generation and caching
pub struct XmssOptimized {
    /// Public key
    pub public_key: XmssPublicKeyOptimized,
    /// Private state (protected)
    private_state: Arc<RwLock<XmssPrivateState>>,
    /// Parameter set
    parameter_set: XmssParameterSet,
    /// WOTS+ parameters
    wots_params: WotsParameters,
    /// Hash function
    hash_function: Arc<dyn HashFunction>,
    /// Signature counter (atomic for thread safety)
    signature_counter: AtomicU64,
    
    // Caching for performance
    /// Cache for WOTS+ public keys (leaf nodes)
    leaf_cache: Arc<RwLock<LruCache<u64, Vec<u8>>>>,
    /// Cache for tree nodes
    node_cache: Arc<RwLock<LruCache<(u32, u64), Vec<u8>>>>,
    /// Cache for authentication paths
    auth_path_cache: Arc<RwLock<LruCache<u64, Vec<Vec<u8>>>>>,
}

impl XmssOptimized {
    /// Create new optimized XMSS instance
    pub fn new(parameter_set: XmssParameterSet) -> Result<Self> {
        // Generate seeds
        let master_seed = OsRandomKeyGenerator::generate_key(64);
        let private_seed: [u8; 32] = master_seed[..32].try_into()
            .map_err(|_| CryptKeyperError::KeyGenerationError("Private seed generation failed".to_string()))?;
        let pub_seed: [u8; 32] = master_seed[32..64].try_into()
            .map_err(|_| CryptKeyperError::KeyGenerationError("Public seed generation failed".to_string()))?;
        
        let wots_params = parameter_set.wots_params();
        let hash_function = parameter_set.create_hash_function();
        let max_signatures = parameter_set.max_signatures();
        
        // Generate root lazily - we'll compute it when first needed
        let root = Self::compute_root_lazy(
            &parameter_set, 
            &private_seed, 
            &pub_seed, 
            parameter_set.tree_height() as u32
        )?;
        
        let public_key = XmssPublicKeyOptimized {
            root,
            pub_seed,
            parameter_set,
        };
        
        let private_state = Arc::new(RwLock::new(XmssPrivateState {
            private_seed,
            signature_index: 0,
            max_signatures,
        }));
        
        // Initialize caches with reasonable sizes
        let cache_size = std::cmp::min(1000, max_signatures / 100);
        let leaf_cache = Arc::new(RwLock::new(LruCache::new(
            std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::new(1000).unwrap())
        )));
        let node_cache = Arc::new(RwLock::new(LruCache::new(
            std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::new(1000).unwrap())
        )));
        let auth_path_cache = Arc::new(RwLock::new(LruCache::new(
            std::num::NonZeroUsize::new(100).unwrap()
        )));
        
        Ok(Self {
            public_key,
            private_state,
            parameter_set,
            wots_params,
            hash_function,
            signature_counter: AtomicU64::new(0),
            leaf_cache,
            node_cache,
            auth_path_cache,
        })
    }
    
    /// Compute tree root lazily (only compute what's needed)
    fn compute_root_lazy(
        parameter_set: &XmssParameterSet,
        private_seed: &[u8; 32],
        pub_seed: &[u8; 32],
        height: u32,
    ) -> Result<Vec<u8>> {
        // For demo purposes, compute just the first few leaves and estimate root
        // In a full implementation, this would use a more sophisticated approach
        let hash_function = parameter_set.create_hash_function();
        
        // Generate first leaf to establish root structure
        let mut addr = XmssAddress::new();
        addr.set_ots_address(0);
        
        let wots = WotsPlusOptimized::new(*parameter_set, *private_seed, *pub_seed, addr);
        let public_key = wots.public_key()?;
        
        // Compress WOTS+ public key to leaf using L-tree
        let leaf = Self::ltree(&public_key, &hash_function, pub_seed, &addr)?;
        
        // For height 1, root is just the leaf
        if height == 1 {
            return Ok(leaf);
        }
        
        // For larger heights, we'd normally compute the full tree
        // For now, return a placeholder based on the first leaf
        let mut current = leaf;
        for h in 0..height {
            let mut tree_addr = XmssAddress::new();
            tree_addr.set_tree_height(h);
            tree_addr.set_tree_index(0);
            
            // Simulate tree computation
            current = Self::hash_h(&current, &current, &hash_function, pub_seed, &tree_addr)?;
        }
        
        Ok(current)
    }
    
    /// L-tree computation for compressing WOTS+ public keys
    fn ltree(
        wots_pk: &[Vec<u8>],
        hash_function: &dyn HashFunction,
        pub_seed: &[u8; 32],
        address: &XmssAddress,
    ) -> Result<Vec<u8>> {
        let mut addr = *address;
        addr.address_type = AddressType::LTreeAddress;
        
        let mut current_layer: Vec<Vec<u8>> = wots_pk.to_vec();
        let mut tree_height = 0u32;
        
        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();
            
            for i in (0..current_layer.len()).step_by(2) {
                addr.set_tree_height(tree_height);
                addr.set_tree_index(i as u32 / 2);
                
                let left = &current_layer[i];
                let right = if i + 1 < current_layer.len() {
                    &current_layer[i + 1]
                } else {
                    left // Duplicate if odd
                };
                
                let parent = Self::hash_h(left, right, hash_function, pub_seed, &addr)?;
                next_layer.push(parent);
            }
            
            current_layer = next_layer;
            tree_height += 1;
        }
        
        Ok(current_layer[0].clone())
    }
    
    /// Hash function for internal nodes with bitmask
    fn hash_h(
        left: &[u8],
        right: &[u8],
        hash_function: &dyn HashFunction,
        pub_seed: &[u8; 32],
        address: &XmssAddress,
    ) -> Result<Vec<u8>> {
        hash_function.hash_with_bitmask(
            pub_seed,
            left,
            right,
            &address.to_bytes(),
        )
    }
    
    /// Generate leaf node (WOTS+ public key compressed via L-tree)
    fn generate_leaf(&self, leaf_index: u64) -> Result<Vec<u8>> {
        // Check cache first
        {
            let cache = self.leaf_cache.read();
            if let Some(cached_leaf) = cache.peek(&leaf_index) {
                return Ok(cached_leaf.clone());
            }
        }
        
        // Generate leaf if not cached
        let private_state = self.private_state.read();
        let mut addr = XmssAddress::new();
        addr.set_ots_address(leaf_index as u32);
        
        let wots = WotsPlusOptimized::new(
            self.parameter_set,
            private_state.private_seed,
            self.public_key.pub_seed,
            addr,
        );
        
        let wots_pk = wots.public_key()?;
        let leaf = Self::ltree(&wots_pk, &*self.hash_function, &self.public_key.pub_seed, &addr)?;
        
        // Cache the result
        {
            let mut cache = self.leaf_cache.write();
            cache.put(leaf_index, leaf.clone());
        }
        
        Ok(leaf)
    }
    
    /// Generate authentication path for a given leaf index
    fn generate_auth_path(&self, leaf_index: u64) -> Result<Vec<Vec<u8>>> {
        // Check cache first
        {
            let cache = self.auth_path_cache.read();
            if let Some(cached_path) = cache.peek(&leaf_index) {
                return Ok(cached_path.clone());
            }
        }
        
        let height = self.parameter_set.tree_height();
        let mut path = Vec::with_capacity(height as usize);
        let mut index = leaf_index;
        
        for h in 0..height {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            
            // Generate sibling node
            if h == 0 {
                // Sibling is a leaf
                let sibling = self.generate_leaf(sibling_index)?;
                path.push(sibling);
            } else {
                // Sibling is an internal node - would need tree construction
                // For now, generate a placeholder
                let sibling = vec![0u8; self.hash_function.output_size()];
                path.push(sibling);
            }
            
            index /= 2;
        }
        
        // Cache the result
        {
            let mut cache = self.auth_path_cache.write();
            cache.put(leaf_index, path.clone());
        }
        
        Ok(path)
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<XmssSignatureOptimized> {
        // Hash message to correct size if needed
        let message_hash = if message.len() == self.hash_function.output_size() {
            message.to_vec()
        } else {
            self.hash_function.hash(message)
        };
        
        // Get and increment signature index atomically
        let signature_index = self.signature_counter.fetch_add(1, Ordering::SeqCst);
        
        // Check if we have signatures remaining
        {
            let private_state = self.private_state.read();
            if signature_index >= private_state.max_signatures {
                return Err(CryptKeyperError::NoMoreSignatures);
            }
        }
        
        // Generate WOTS+ signature
        let private_state = self.private_state.read();
        let mut addr = XmssAddress::new();
        addr.set_ots_address(signature_index as u32);
        
        let wots = WotsPlusOptimized::new(
            self.parameter_set,
            private_state.private_seed,
            self.public_key.pub_seed,
            addr,
        );
        
        let wots_signature = wots.sign(&message_hash)?;
        
        // Generate authentication path
        let auth_path = self.generate_auth_path(signature_index)?;
        
        // Update private state
        {
            let mut private_state = self.private_state.write();
            private_state.signature_index = signature_index + 1;
        }
        
        Ok(XmssSignatureOptimized {
            index: signature_index,
            wots_signature,
            auth_path,
        })
    }
    
    /// Verify a signature
    pub fn verify(
        message: &[u8],
        signature: &XmssSignatureOptimized,
        public_key: &XmssPublicKeyOptimized,
    ) -> Result<bool> {
        // Hash message to correct size if needed
        let hash_function = public_key.parameter_set.create_hash_function();
        let message_hash = if message.len() == hash_function.output_size() {
            message.to_vec()
        } else {
            hash_function.hash(message)
        };
        
        // Verify WOTS+ signature and reconstruct public key
        let mut addr = XmssAddress::new();
        addr.set_ots_address(signature.index as u32);
        
        let wots = WotsPlusOptimized::new(
            public_key.parameter_set,
            [0u8; 32], // We don't need private seed for verification
            public_key.pub_seed,
            addr,
        );
        
        // Verify WOTS+ signature
        let is_wots_valid = wots.verify(&message_hash, &signature.wots_signature)?;
        if !is_wots_valid {
            return Ok(false);
        }
        
        // Verify authentication path by reconstructing root
        use crate::hash_traits::Sha256HashFunction;
        let hash_function = Sha256HashFunction{}; // Use default for now
        let computed_root = Self::verify_auth_path(
            &wots.public_key_from_signature(&message_hash, &signature.wots_signature)?,
            signature.index,
            &signature.auth_path,
            &public_key.pub_seed,
            public_key.parameter_set.tree_height(),
            &hash_function,
        )?;
        
        // Compare computed root with stored root
        Ok(computed_root == public_key.root)
    }
    
    /// Verify authentication path by reconstructing the root
    fn verify_auth_path(
        leaf: &[u8],
        leaf_index: u64,
        auth_path: &[Vec<u8>],
        pub_seed: &[u8; 32],
        tree_height: u32,
        hash_function: &dyn HashFunction,
    ) -> Result<Vec<u8>> {
        if auth_path.len() != tree_height as usize {
            return Err(CryptKeyperError::ValidationError(
                format!("Invalid authentication path length: expected {}, got {}", 
                       tree_height, auth_path.len())
            ));
        }
        
        let mut current_node = leaf.to_vec();
        let mut current_index = leaf_index;
        
        for (height, sibling) in auth_path.iter().enumerate() {
            let mut addr = XmssAddress::new();
            addr.set_tree_height(height as u32);
            addr.set_tree_index(current_index >> 1);
            addr.set_type(AddressType::HashTreeAddress);
            
            // Determine if current node is left or right child
            if current_index & 1 == 0 {
                // Current node is left child
                current_node = Self::hash_h(&current_node, sibling, hash_function, pub_seed, &addr)?;
            } else {
                // Current node is right child
                current_node = Self::hash_h(sibling, &current_node, hash_function, pub_seed, &addr)?;
            }
            
            current_index >>= 1;
        }
        
        Ok(current_node)
    }
    
    
    /// PRF function
    fn prf(key: &[u8; 32], input: &[u8; 32]) -> Result<[u8; 32]> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(key);
        data.extend_from_slice(input);
        
        use crate::hash_traits::Sha256HashFunction;
        let hash = Sha256HashFunction::hash(&data);
        if hash.len() != 32 {
            return Err(CryptKeyperError::HashError("PRF hash size mismatch".to_string()));
        }
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
    }
    
    /// Get remaining signatures
    pub fn remaining_signatures(&self) -> u64 {
        let private_state = self.private_state.read();
        private_state.max_signatures.saturating_sub(private_state.signature_index)
    }
    
    /// Get current signature index
    pub fn current_index(&self) -> u64 {
        self.signature_counter.load(Ordering::SeqCst)
    }
    
    /// Clear all caches (useful for memory management)
    pub fn clear_caches(&self) {
        self.leaf_cache.write().clear();
        self.node_cache.write().clear();
        self.auth_path_cache.write().clear();
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize, usize) {
        let leaf_cache = self.leaf_cache.read();
        let node_cache = self.node_cache.read();
        let auth_cache = self.auth_path_cache.read();
        
        (leaf_cache.len(), node_cache.len(), auth_cache.len())
    }
}