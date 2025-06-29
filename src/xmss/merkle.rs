use std::convert::TryInto;

use crate::hash_function::hash_function::Sha256HashFunction;
use crate::xmss::address::XmssAddress;
use crate::errors::{CryptKeyperError, Result};

/// Merkle Tree for XMSS with proper address handling
pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub tree: Vec<Vec<[u8; 32]>>,
    pub root: Option<[u8; 32]>,
    pub height: usize,
}

impl MerkleTree {
    /// Create new Merkle tree from leaves with proper XMSS addressing
    pub fn new(leaves: Vec<[u8; 32]>, pub_seed: &[u8; 32]) -> Result<Self> {
        if leaves.is_empty() || !leaves.len().is_power_of_two() {
            return Err(CryptKeyperError::InvalidParameter(
                "Leaves count must be a power of 2 and non-empty".to_string()
            ));
        }
        
        let height = leaves.len().trailing_zeros() as usize;
        let mut tree = vec![leaves.clone()];
        let mut current_layer = leaves.clone();
        let mut layer_height = 0usize;

        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();

            for i in (0..current_layer.len()).step_by(2) {
                let mut addr = XmssAddress::new();
                addr.set_tree_address(i as u32 / 2);
                addr.set_tree_height(layer_height as u32);
                addr.set_tree_index(i as u32 / 2);
                
                let left = current_layer[i];
                let right = if i + 1 < current_layer.len() {
                    current_layer[i + 1]
                } else {
                    left // Duplicate if odd number
                };
                
                let hashed = Self::hash_h(&left, &right, pub_seed, &addr)?;
                next_layer.push(hashed);
            }

            tree.push(next_layer.clone());
            current_layer = next_layer;
            layer_height += 1;
        }

        let root = current_layer.first().cloned();

        Ok(MerkleTree {
            leaves,
            tree,
            root,
            height,
        })
    }

    /// Hash function for internal nodes with bitmask
    fn hash_h(left: &[u8; 32], right: &[u8; 32], pub_seed: &[u8; 32], address: &XmssAddress) -> Result<[u8; 32]> {
        let mut addr = *address;
        addr.set_key_and_mask(0);
        let key = Self::prf(pub_seed, &addr.to_bytes())?;
        
        addr.set_key_and_mask(1);
        let bitmask_left = Self::prf(pub_seed, &addr.to_bytes())?;
        
        addr.set_key_and_mask(2);
        let bitmask_right = Self::prf(pub_seed, &addr.to_bytes())?;
        
        let mut masked_left = [0u8; 32];
        let mut masked_right = [0u8; 32];
        
        for i in 0..32 {
            masked_left[i] = left[i] ^ bitmask_left[i];
            masked_right[i] = right[i] ^ bitmask_right[i];
        }
        
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&key);
        data.extend_from_slice(&masked_left);
        data.extend_from_slice(&masked_right);
        
        let hash = Sha256HashFunction::hash(&data);
        hash.try_into()
            .map_err(|_| CryptKeyperError::HashError("Hash size mismatch".to_string()))
    }
    
    /// PRF function
    fn prf(key: &[u8; 32], input: &[u8; 32]) -> Result<[u8; 32]> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(key);
        data.extend_from_slice(input);
        
        let hash = Sha256HashFunction::hash(&data);
        hash.try_into()
            .map_err(|_| CryptKeyperError::HashError("PRF hash size mismatch".to_string()))
    }
    
    /// Get authentication path for leaf at given index
    pub fn get_auth_path(&self, index: usize) -> Result<Vec<[u8; 32]>> {
        if index >= self.leaves.len() {
            return Err(CryptKeyperError::InvalidSignatureIndex(index));
        }
        
        let mut path = Vec::new();
        let mut idx = index;

        for layer in &self.tree[..self.tree.len()-1] { // Exclude root layer
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            
            if sibling_idx < layer.len() {
                path.push(layer[sibling_idx]);
            } else {
                path.push(layer[idx]); // Self if no sibling
            }
            
            idx /= 2;
        }
        
        Ok(path)
    }

    /// Get the root of the tree
    pub fn root(&self) -> Option<[u8; 32]> {
        self.root
    }
    
    /// Verify authentication path
    pub fn verify_auth_path(
        leaf: &[u8; 32], 
        index: usize, 
        auth_path: &[[u8; 32]], 
        root: &[u8; 32],
        pub_seed: &[u8; 32]
    ) -> Result<bool> {
        let mut current_hash = *leaf;
        let mut idx = index;
        
        for (height, &sibling) in auth_path.iter().enumerate() {
            let mut addr = XmssAddress::new();
            addr.set_tree_height(height as u32);
            addr.set_tree_index(idx as u32 / 2);
            
            current_hash = if idx % 2 == 0 {
                Self::hash_h(&current_hash, &sibling, pub_seed, &addr)?
            } else {
                Self::hash_h(&sibling, &current_hash, pub_seed, &addr)?
            };
            
            idx /= 2;
        }
        
        Ok(current_hash == *root)
    }
}
