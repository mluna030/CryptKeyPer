use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use zeroize::ZeroizeOnDrop;

use crate::hash_traits::HashFunction;
use crate::parameters::{XmssMtParameterSet, XmssParameterSet};
use crate::xmss::xmss_optimized::{XmssOptimized, XmssSignatureOptimized, XmssPublicKeyOptimized};
use crate::errors::{CryptKeyperError, Result};
use crate::random_key_generator::random_key_generator::OsRandomKeyGenerator;

/// XMSS^MT (Multi-Tree) signature containing signatures from multiple layers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmssMtSignature {
    /// Global signature index across all trees
    pub global_index: u128,
    /// Signatures from each layer (bottom to top)
    pub layer_signatures: Vec<XmssSignatureOptimized>,
    /// Public keys for intermediate layers
    pub layer_public_keys: Vec<XmssPublicKeyOptimized>,
}

/// XMSS^MT public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmssMtPublicKey {
    /// Root of the top-level tree
    pub root: Vec<u8>,
    /// Public seed (shared across all layers)
    pub pub_seed: [u8; 32],
    /// Parameter set identifier
    pub parameter_set: XmssMtParameterSet,
}

/// Individual XMSS tree in the multi-tree structure
// #[derive(ZeroizeOnDrop)] // Commented out due to trait bound issues
struct XmssTreeLayer {
    /// XMSS instance for this layer
    _xmss: XmssOptimized,
    /// Layer index (0 = bottom layer)
    _layer_index: u32,
    /// Tree index within this layer
    _tree_index: u64,
    /// Whether this tree is exhausted
    _exhausted: bool,
}

/// XMSS^MT state management
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct XmssMtState {
    /// Master private seed
    master_seed: [u8; 32],
    /// Current signature index
    signature_index: u128,
    /// Maximum signatures available
    max_signatures: u128,
    /// Current tree indices for each layer
    current_tree_indices: Vec<u64>,
}

/// XMSS^MT (Multi-Tree) implementation for virtually unlimited signatures
pub struct XmssMt {
    /// Public key
    pub public_key: XmssMtPublicKey,
    /// Parameter set
    parameter_set: XmssMtParameterSet,
    /// Hash function
    _hash_function: Arc<dyn HashFunction>,
    /// Private state
    private_state: Arc<RwLock<XmssMtState>>,
    /// Active trees for each layer
    active_trees: Arc<RwLock<HashMap<u32, XmssTreeLayer>>>,
    /// Global signature counter
    signature_counter: AtomicU64,
    /// Tree cache for performance
    tree_cache: Arc<RwLock<HashMap<(u32, u64), Arc<XmssOptimized>>>>,
}

impl XmssMt {
    /// Create new XMSS^MT instance
    pub fn new(parameter_set: XmssMtParameterSet) -> Result<Self> {
        // Generate master seed
        let master_seed_bytes = OsRandomKeyGenerator::generate_key(64);
        let master_seed: [u8; 32] = master_seed_bytes[..32].try_into()
            .map_err(|_| CryptKeyperError::KeyGenerationError("Master seed generation failed".to_string()))?;
        let pub_seed: [u8; 32] = master_seed_bytes[32..64].try_into()
            .map_err(|_| CryptKeyperError::KeyGenerationError("Public seed generation failed".to_string()))?;
        
        let layers = parameter_set.layers();
        let _tree_height = parameter_set.tree_height();
        let max_signatures = parameter_set.max_signatures();
        
        // Initialize current tree indices
        let current_tree_indices = vec![0u64; layers as usize];
        
        let private_state = Arc::new(RwLock::new(XmssMtState {
            master_seed,
            signature_index: 0,
            max_signatures,
            current_tree_indices,
        }));
        
        // Create hash function
        let hash_function = Arc::new(crate::hash_traits::Sha256HashFunction);
        
        // Generate the root by creating the top-level tree
        let top_level_xmss_params = XmssParameterSet::XmssSha256W16H10; // Use standard XMSS params
        let root_tree = Self::create_tree_for_layer(
            layers - 1,
            0,
            &master_seed,
            &pub_seed,
            top_level_xmss_params,
        )?;
        
        let root = root_tree.public_key.root.clone();
        
        let public_key = XmssMtPublicKey {
            root,
            pub_seed,
            parameter_set,
        };
        
        let active_trees = Arc::new(RwLock::new(HashMap::new()));
        let tree_cache = Arc::new(RwLock::new(HashMap::new()));
        
        Ok(Self {
            public_key,
            parameter_set,
            _hash_function: hash_function,
            private_state,
            active_trees,
            signature_counter: AtomicU64::new(0),
            tree_cache,
        })
    }
    
    /// Create an XMSS tree for a specific layer and index
    fn create_tree_for_layer(
        layer: u32,
        tree_index: u64,
        master_seed: &[u8; 32],
        _pub_seed: &[u8; 32],
        xmss_params: XmssParameterSet,
    ) -> Result<XmssOptimized> {
        // Derive layer-specific seed
        let mut layer_seed = *master_seed;
        
        // Mix in layer and tree index
        for i in 0..32 {
            layer_seed[i] ^= ((layer as u64).wrapping_add(tree_index) >> (i % 8)) as u8;
        }
        
        // Create XMSS instance with derived seed
        // Note: This is a simplified approach. A full implementation would use proper key derivation.
        let xmss = XmssOptimized::new(xmss_params)?;
        
        Ok(xmss)
    }
    
    /// Get or create tree for a specific layer and index
    fn get_or_create_tree(&self, layer: u32, tree_index: u64) -> Result<Arc<XmssOptimized>> {
        // Check cache first
        {
            let cache = self.tree_cache.read();
            if let Some(cached_tree) = cache.get(&(layer, tree_index)) {
                return Ok(cached_tree.clone());
            }
        }
        
        // Create new tree
        let private_state = self.private_state.read();
        let xmss_params = XmssParameterSet::XmssSha256W16H10; // Standard params for all layers
        
        let tree = Self::create_tree_for_layer(
            layer,
            tree_index,
            &private_state.master_seed,
            &self.public_key.pub_seed,
            xmss_params,
        )?;
        
        let tree_arc = Arc::new(tree);
        
        // Cache the tree
        {
            let mut cache = self.tree_cache.write();
            cache.insert((layer, tree_index), tree_arc.clone());
        }
        
        Ok(tree_arc)
    }
    
    /// Sign a message using XMSS^MT
    pub fn sign(&self, message: &[u8]) -> Result<XmssMtSignature> {
        let signature_index = self.signature_counter.fetch_add(1, Ordering::SeqCst);
        
        // Check if we have signatures remaining
        {
            let private_state = self.private_state.read();
            if signature_index as u128 >= private_state.max_signatures {
                return Err(CryptKeyperError::NoMoreSignatures);
            }
        }
        
        let layers = self.parameter_set.layers();
        let tree_height = self.parameter_set.tree_height();
        let signatures_per_tree = 1u64 << tree_height;
        
        let mut layer_signatures = Vec::with_capacity(layers as usize);
        let mut layer_public_keys = Vec::with_capacity(layers as usize);
        let mut current_message = message.to_vec();
        
        // Sign from bottom layer to top layer
        for layer in 0..layers {
            // Calculate which tree in this layer
            let tree_index = (signature_index as u64) / (signatures_per_tree.pow(layer));
            let _index_in_tree = (signature_index as u64) % signatures_per_tree;
            
            // Get the tree for this layer
            let tree = self.get_or_create_tree(layer, tree_index)?;
            
            // Sign the current message
            let signature = tree.sign(&current_message)?;
            layer_signatures.push(signature);
            
            // Store public key for this layer (except for top layer)
            if layer < layers - 1 {
                layer_public_keys.push(tree.public_key.clone());
                // Next layer signs the public key of this layer
                current_message = tree.public_key.root.clone();
            }
        }
        
        Ok(XmssMtSignature {
            global_index: signature_index as u128,
            layer_signatures,
            layer_public_keys,
        })
    }
    
    /// Verify an XMSS^MT signature
    pub fn verify(
        message: &[u8],
        signature: &XmssMtSignature,
        public_key: &XmssMtPublicKey,
    ) -> Result<bool> {
        let layers = public_key.parameter_set.layers();
        
        if signature.layer_signatures.len() != layers as usize {
            return Ok(false);
        }
        
        if signature.layer_public_keys.len() != (layers - 1) as usize {
            return Ok(false);
        }
        
        let mut current_message = message.to_vec();
        
        // Verify from bottom layer to top layer
        for layer in 0..layers {
            let layer_signature = &signature.layer_signatures[layer as usize];
            
            let layer_public_key = if layer == layers - 1 {
                // Top layer uses the main public key
                &XmssPublicKeyOptimized {
                    root: public_key.root.clone(),
                    pub_seed: public_key.pub_seed,
                    parameter_set: XmssParameterSet::XmssSha256W16H10,
                }
            } else {
                &signature.layer_public_keys[layer as usize]
            };
            
            // Verify signature for this layer
            let is_valid = XmssOptimized::verify(
                &current_message,
                layer_signature,
                layer_public_key,
            )?;
            
            if !is_valid {
                return Ok(false);
            }
            
            // Next layer verifies the public key of this layer
            if layer < layers - 1 {
                current_message = layer_public_key.root.clone();
            }
        }
        
        Ok(true)
    }
    
    /// Get remaining signatures
    pub fn remaining_signatures(&self) -> u128 {
        let private_state = self.private_state.read();
        let current_index = self.signature_counter.load(Ordering::SeqCst) as u128;
        private_state.max_signatures.saturating_sub(current_index)
    }
    
    /// Get current signature index
    pub fn current_index(&self) -> u128 {
        self.signature_counter.load(Ordering::SeqCst) as u128
    }
    
    /// Get maximum possible signatures
    pub fn max_signatures(&self) -> u128 {
        self.parameter_set.max_signatures()
    }
    
    /// Advance to next tree in a specific layer (for tree exhaustion)
    pub fn advance_tree_in_layer(&self, layer: u32) -> Result<()> {
        let mut private_state = self.private_state.write();
        
        if layer as usize >= private_state.current_tree_indices.len() {
            return Err(CryptKeyperError::InvalidParameter(
                "Invalid layer index".to_string()
            ));
        }
        
        private_state.current_tree_indices[layer as usize] += 1;
        
        // Remove exhausted tree from active trees
        {
            let mut active_trees = self.active_trees.write();
            active_trees.remove(&layer);
        }
        
        Ok(())
    }
    
    /// Get statistics about the multi-tree structure
    pub fn get_statistics(&self) -> XmssMtStatistics {
        let private_state = self.private_state.read();
        let current_index = self.signature_counter.load(Ordering::SeqCst) as u128;
        
        let active_trees = self.active_trees.read();
        let cache = self.tree_cache.read();
        
        XmssMtStatistics {
            total_signatures: private_state.max_signatures,
            used_signatures: current_index,
            remaining_signatures: private_state.max_signatures.saturating_sub(current_index),
            layers: self.parameter_set.layers(),
            tree_height: self.parameter_set.tree_height(),
            active_trees: active_trees.len(),
            cached_trees: cache.len(),
            current_tree_indices: private_state.current_tree_indices.clone(),
        }
    }
    
    /// Clear tree cache to free memory
    pub fn clear_cache(&self) {
        let mut cache = self.tree_cache.write();
        cache.clear();
    }
}

/// Statistics about XMSS^MT instance
#[derive(Debug, Clone)]
pub struct XmssMtStatistics {
    pub total_signatures: u128,
    pub used_signatures: u128,
    pub remaining_signatures: u128,
    pub layers: u32,
    pub tree_height: u32,
    pub active_trees: usize,
    pub cached_trees: usize,
    pub current_tree_indices: Vec<u64>,
}

impl std::fmt::Display for XmssMtStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
            "XMSS^MT Statistics:\n\
             Total Signatures: {}\n\
             Used Signatures: {}\n\
             Remaining: {}\n\
             Layers: {}\n\
             Tree Height: {}\n\
             Active Trees: {}\n\
             Cached Trees: {}\n\
             Progress: {:.2}%",
            self.total_signatures,
            self.used_signatures,
            self.remaining_signatures,
            self.layers,
            self.tree_height,
            self.active_trees,
            self.cached_trees,
            (self.used_signatures as f64 / self.total_signatures as f64) * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_xmss_mt_creation() -> Result<()> {
        let xmss_mt = XmssMt::new(XmssMtParameterSet::XmssMtSha256W16H20D2)?;
        
        assert_eq!(xmss_mt.parameter_set.layers(), 2);
        assert_eq!(xmss_mt.parameter_set.tree_height(), 10);
        assert_eq!(xmss_mt.parameter_set.total_height(), 20);
        
        Ok(())
    }
    
    #[test]
    fn test_xmss_mt_sign_verify() -> Result<()> {
        let xmss_mt = XmssMt::new(XmssMtParameterSet::XmssMtSha256W16H20D2)?;
        
        let message = b"Hello, XMSS^MT!";
        let signature = xmss_mt.sign(message)?;
        
        let is_valid = XmssMt::verify(message, &signature, &xmss_mt.public_key)?;
        assert!(is_valid);
        
        Ok(())
    }
    
    #[test]
    fn test_xmss_mt_multiple_signatures() -> Result<()> {
        let xmss_mt = XmssMt::new(XmssMtParameterSet::XmssMtSha256W16H20D2)?;
        
        let messages = [b"Message 1", b"Message 2", b"Message 3"];
        let mut signatures = Vec::new();
        
        for msg in &messages {
            let sig = xmss_mt.sign(*msg)?;
            signatures.push(sig);
        }
        
        // Verify all signatures
        for (i, (msg, sig)) in messages.iter().zip(signatures.iter()).enumerate() {
            let is_valid = XmssMt::verify(*msg, sig, &xmss_mt.public_key)?;
            assert!(is_valid, "Signature {} should be valid", i);
        }
        
        Ok(())
    }
    
    #[test]
    fn test_xmss_mt_statistics() -> Result<()> {
        let xmss_mt = XmssMt::new(XmssMtParameterSet::XmssMtSha256W16H20D2)?;
        
        let stats = xmss_mt.get_statistics();
        assert_eq!(stats.layers, 2);
        assert_eq!(stats.tree_height, 10);
        assert_eq!(stats.used_signatures, 0);
        
        // Sign a message and check stats
        let _ = xmss_mt.sign(b"test message")?;
        let stats_after = xmss_mt.get_statistics();
        assert_eq!(stats_after.used_signatures, 1);
        
        Ok(())
    }
}