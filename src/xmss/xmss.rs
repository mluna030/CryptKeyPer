use std::convert::TryInto;
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};

use crate::hash_function::hash_function::Sha256HashFunction;
use crate::random_key_generator::random_key_generator::OsRandomKeyGenerator;
use crate::xmss::merkle::MerkleTree;
use crate::xmss::wots::WotsPlus;
use crate::xmss::address::{XmssAddress, AddressType};
use crate::errors::{CryptKeyperError, Result};

/// XMSS Signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmssSignature {
    pub index: u32,
    pub wots_signature: Vec<[u8; 32]>,
    pub auth_path: Vec<[u8; 32]>,
}

/// XMSS Public Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmssPublicKey {
    pub root: [u8; 32],
    pub pub_seed: [u8; 32],
}

/// XMSS Private Key State
#[derive(ZeroizeOnDrop)]
struct XmssPrivateState {
    private_seed: [u8; 32],
    index: u32,
    #[zeroize(skip)]
    max_signatures: u32,
}

/// XMSS One-Time Signature Scheme
pub struct Xmss {
    pub public_key: XmssPublicKey,
    private_state: XmssPrivateState,
    merkle_tree: MerkleTree,
}

impl Xmss {
    /// Create new XMSS instance with specified height (2^height signatures)
    pub fn new(height: u32) -> Result<Self> {
        if height == 0 || height > 20 {
            return Err(CryptKeyperError::InvalidParameter(
                "Height must be between 1 and 20".to_string()
            ));
        }
        
        let max_signatures = 1u32 << height;
        
        // Generate seeds
        let master_seed = OsRandomKeyGenerator::generate_key(64);
        let private_seed: [u8; 32] = master_seed[..32].try_into()
            .map_err(|_| CryptKeyperError::KeyGenerationError("Private seed generation failed".to_string()))?;
        let pub_seed: [u8; 32] = master_seed[32..64].try_into()
            .map_err(|_| CryptKeyperError::KeyGenerationError("Public seed generation failed".to_string()))?;
        
        // Generate all WOTS+ public keys for the tree
        let mut leaves = Vec::with_capacity(max_signatures as usize);
        
        for i in 0..max_signatures {
            let mut addr = XmssAddress::new();
            addr.set_ots_address(i);
            
            let wots = WotsPlus::keygen(&private_seed, &pub_seed, &addr)?;
            let ltree_pk = Self::ltree(wots.public_key(), &pub_seed, &addr)?;
            leaves.push(ltree_pk);
        }
        
        // Build Merkle tree
        let merkle_tree = MerkleTree::new(leaves, &pub_seed)?;
        let root = merkle_tree.root()
            .ok_or_else(|| CryptKeyperError::KeyGenerationError("Failed to compute tree root".to_string()))?;
        
        let public_key = XmssPublicKey {
            root,
            pub_seed,
        };
        
        let private_state = XmssPrivateState {
            private_seed,
            index: 0,
            max_signatures,
        };
        
        Ok(Xmss {
            public_key,
            private_state,
            merkle_tree,
        })
    }

    /// L-tree computation for WOTS+ public key compression
    fn ltree(wots_pk: &[[u8; 32]], pub_seed: &[u8; 32], address: &XmssAddress) -> Result<[u8; 32]> {
        let mut addr = *address;
        addr.address_type = AddressType::LTreeAddress;
        
        let _len = wots_pk.len();
        let mut current_layer: Vec<[u8; 32]> = wots_pk.to_vec();
        let mut tree_height = 0u32;
        
        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();
            
            for i in (0..current_layer.len()).step_by(2) {
                addr.set_tree_height(tree_height);
                addr.set_tree_index(i as u32 / 2);
                
                let left = current_layer[i];
                let right = if i + 1 < current_layer.len() {
                    current_layer[i + 1]
                } else {
                    left // Duplicate if odd
                };
                
                let parent = Self::hash_h(&left, &right, pub_seed, &addr)?;
                next_layer.push(parent);
            }
            
            current_layer = next_layer;
            tree_height += 1;
        }
        
        Ok(current_layer[0])
    }
    
    /// Hash function for internal nodes
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
    
    /// Sign a message
    pub fn sign(&mut self, message: &[u8; 32]) -> Result<XmssSignature> {
        if self.private_state.index >= self.private_state.max_signatures {
            return Err(CryptKeyperError::NoMoreSignatures);
        }
        
        let index = self.private_state.index;
        
        // Generate WOTS+ signature
        let mut addr = XmssAddress::new();
        addr.set_ots_address(index);
        
        let wots = WotsPlus::keygen(&self.private_state.private_seed, &self.public_key.pub_seed, &addr)?;
        let wots_signature = wots.sign(message, &self.public_key.pub_seed, &addr)?;
        
        // Get authentication path
        let auth_path = self.merkle_tree.get_auth_path(index as usize)?;
        
        // Increment index
        self.private_state.index += 1;
        
        Ok(XmssSignature {
            index,
            wots_signature,
            auth_path,
        })
    }

    /// Verify an XMSS signature
    pub fn verify(
        message: &[u8; 32],
        signature: &XmssSignature,
        public_key: &XmssPublicKey,
    ) -> Result<bool> {
        // Verify index bounds (reasonable maximum)
        if signature.index >= (1u32 << 20) { // Max height of 20 (2^20 = ~1M signatures)
            return Ok(false);
        }
        
        // Reconstruct WOTS+ public key from signature
        let mut addr = XmssAddress::new();
        addr.set_ots_address(signature.index);
        
        // Reconstruct WOTS+ public key from signature
        let mut reconstructed_pk = Vec::with_capacity(67); // WOTS_LEN
        let msg_base_w = WotsPlus::base_w(message);
        
        for (i, (&digit, &sig_i)) in msg_base_w.iter().zip(signature.wots_signature.iter()).enumerate() {
            addr.set_chain_address(i as u32);
            addr.set_hash_address(digit);
            
            let pk_from_sig = WotsPlus::chain(sig_i, digit, 15 - digit, &public_key.pub_seed, &addr)?; // WOTS_W - 1 - digit
            reconstructed_pk.push(pk_from_sig);
        }
        
        // Compress WOTS+ public key using L-tree
        let leaf = Self::ltree(&reconstructed_pk, &public_key.pub_seed, &addr)?;
        
        // Verify authentication path
        MerkleTree::verify_auth_path(
            &leaf,
            signature.index as usize,
            &signature.auth_path,
            &public_key.root,
            &public_key.pub_seed,
        )
    }
    
    /// Get remaining signatures
    pub fn remaining_signatures(&self) -> u32 {
        self.private_state.max_signatures - self.private_state.index
    }
    
    /// Get current signature index
    pub fn current_index(&self) -> u32 {
        self.private_state.index
    }
}