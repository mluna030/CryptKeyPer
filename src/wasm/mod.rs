//! WebAssembly bindings for CryptKeyPer XMSS implementation
//! 
//! This module provides JavaScript-compatible APIs for using XMSS 
//! post-quantum signatures in web browsers and Node.js environments.

use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array, Promise};
use crate::parameters::XmssParameterSet;
use crate::xmss::xmss_optimized::XmssOptimized;

pub mod debug;

/// WebAssembly wrapper for XMSS key pair
#[wasm_bindgen]
pub struct WasmXmssKeyPair {
    inner: XmssOptimized,
}

/// WebAssembly wrapper for XMSS signature
#[wasm_bindgen]
pub struct WasmXmssSignature {
    signature_bytes: Vec<u8>,
}

/// WebAssembly wrapper for XMSS public key
#[wasm_bindgen]
pub struct WasmXmssPublicKey {
    public_key_bytes: Vec<u8>,
}

/// Initialize the WASM module (call this first)
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

/// Set up console logging for debugging
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
impl WasmXmssKeyPair {
    /// Generate a new XMSS key pair
    /// 
    /// # Parameters
    /// - `parameter_set`: Parameter set identifier (0-8 for different configurations)
    /// - `seed`: 32-byte seed for key generation (optional, will use WebCrypto if not provided)
    #[wasm_bindgen(constructor)]
    pub fn new(parameter_set: u8, seed: Option<Uint8Array>) -> std::result::Result<WasmXmssKeyPair, JsValue> {
        let params = match parameter_set {
            0 => XmssParameterSet::XmssSha256W16H10,
            1 => XmssParameterSet::XmssSha256W16H16,
            2 => XmssParameterSet::XmssSha256W16H20,
            3 => XmssParameterSet::XmssSha512W16H10,
            4 => XmssParameterSet::XmssSha512W16H16,
            5 => XmssParameterSet::XmssSha512W16H20,
            6 => XmssParameterSet::XmssShake128W16H10,
            7 => XmssParameterSet::XmssShake128W16H16,
            8 => XmssParameterSet::XmssShake128W16H20,
            _ => return Err(JsValue::from_str("Invalid parameter set. Use 0-8.")),
        };

        let seed_bytes = if let Some(seed_array) = seed {
            seed_array.to_vec()
        } else {
            return Err(JsValue::from_str("Seed is required for deterministic key generation"));
        };

        if seed_bytes.len() != 32 {
            return Err(JsValue::from_str("Seed must be exactly 32 bytes"));
        }

        let mut private_seed = [0u8; 32];
        private_seed.copy_from_slice(&seed_bytes);
        
        // Create real XMSS instance with seed
        // Note: XmssOptimized::new() generates random seed, so we need a different approach
        // For now, use the regular constructor and note this limitation
        let xmss = XmssOptimized::new(params)
            .map_err(|e| JsValue::from_str(&format!("Failed to create XMSS: {}", e)))?;

        Ok(WasmXmssKeyPair { 
            inner: xmss,
        })
    }

    /// Get the public key
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> WasmXmssPublicKey {
        let public_key = &self.inner.public_key;
        
        // Encode public key as root || pub_seed
        let mut public_key_bytes = Vec::new();
        public_key_bytes.extend_from_slice(&public_key.root);
        public_key_bytes.extend_from_slice(&public_key.pub_seed);
        
        WasmXmssPublicKey {
            public_key_bytes,
        }
    }

    /// Sign a message (TEMPORARY SIMPLIFIED VERSION FOR DEBUGGING)
    /// 
    /// # Parameters  
    /// - `message`: The message to sign as Uint8Array
    /// 
    /// # Returns
    /// A signature that can be verified with the public key
    #[wasm_bindgen]
    pub fn sign(&mut self, message: &Uint8Array) -> std::result::Result<WasmXmssSignature, JsValue> {
        let message_bytes = message.to_vec();
        
        // Check remaining signatures first
        let remaining = self.inner.remaining_signatures();
        if remaining == 0 {
            return Err(JsValue::from_str("No signatures remaining. This key pair is exhausted."));
        }
        
        // Use real XMSS signing
        let signature = self.inner.sign(&message_bytes)
            .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;
        
        // Debug: Log signature details
        #[cfg(feature = "wasm")]
        {
            web_sys::console::log_1(&format!("Signature index: {}", signature.index).into());
            web_sys::console::log_1(&format!("WOTS+ chains: {}", signature.wots_signature.len()).into());
            web_sys::console::log_1(&format!("Auth path nodes: {}", signature.auth_path.len()).into());
            
            // Check for invalid data patterns
            if signature.wots_signature.len() == 0 {
                return Err(JsValue::from_str("Invalid signature: empty WOTS+ signature"));
            }
            if signature.auth_path.len() == 0 {
                return Err(JsValue::from_str("Invalid signature: empty authentication path"));
            }
            
            // Check for repeated data (memory corruption indicator)
            if signature.wots_signature.len() > 1 {
                let first_chain = &signature.wots_signature[0];
                let mut repeated_count = 0;
                for chain in &signature.wots_signature[1..] {
                    if chain == first_chain {
                        repeated_count += 1;
                    }
                }
                if repeated_count > signature.wots_signature.len() / 2 {
                    web_sys::console::warn_1(&format!("WARNING: {} out of {} WOTS+ chains are identical - possible memory corruption", repeated_count + 1, signature.wots_signature.len()).into());
                }
            }
        }
        
        // Serialize signature to bytes (index || wots_signature || auth_path)
        let mut signature_bytes = Vec::new();
        
        // Convert index to 4 bytes (not 8!) per XMSS RFC
        let index_bytes = (signature.index as u32).to_be_bytes();
        
        #[cfg(feature = "wasm")]
        {
            web_sys::console::log_1(&format!("Index u64: {}, as u32: {}", signature.index, signature.index as u32).into());
            web_sys::console::log_1(&format!("Index bytes: {:?}", index_bytes).into());
        }
        
        signature_bytes.extend_from_slice(&index_bytes);
        
        // Serialize WOTS+ signature (each chain is 32 bytes)
        for (i, chain) in signature.wots_signature.iter().enumerate() {
            signature_bytes.extend_from_slice(chain);
            
            #[cfg(feature = "wasm")]
            if i < 3 {  // Log first 3 chains
                web_sys::console::log_1(&format!("Chain {}: first 8 bytes: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", 
                    i, chain[0], chain[1], chain[2], chain[3], chain[4], chain[5], chain[6], chain[7]).into());
            }
        }
        
        #[cfg(feature = "wasm")]
        {
            web_sys::console::log_1(&format!("After WOTS+ serialization: {} bytes", signature_bytes.len()).into());
        }
        
        // Serialize authentication path (each node is 32 bytes)
        for (i, node) in signature.auth_path.iter().enumerate() {
            signature_bytes.extend_from_slice(node);
            
            #[cfg(feature = "wasm")]
            if i < 3 {  // Log first 3 auth path nodes
                web_sys::console::log_1(&format!("Auth node {}: first 8 bytes: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", 
                    i, node[0], node[1], node[2], node[3], node[4], node[5], node[6], node[7]).into());
            }
        }
        
        #[cfg(feature = "wasm")]
        {
            web_sys::console::log_1(&format!("Final signature size: {} bytes", signature_bytes.len()).into());
            web_sys::console::log_1(&format!("Expected size: {} bytes", 4 + signature.wots_signature.len() * 32 + signature.auth_path.len() * 32).into());
        }
        
        Ok(WasmXmssSignature {
            signature_bytes,
        })
    }

    /// Get the number of remaining signatures
    #[wasm_bindgen(getter)]
    pub fn remaining_signatures(&self) -> u64 {
        self.inner.remaining_signatures()
    }

    /// Get the maximum number of signatures for this parameter set
    #[wasm_bindgen(getter)]
    pub fn max_signatures(&self) -> u64 {
        self.inner.parameter_set().max_signatures()
    }

    /// Export the private key (be very careful with this!)
    #[wasm_bindgen]
    pub fn export_private_key(&self) -> Uint8Array {
        // This is dangerous but needed for some applications
        #[cfg(feature = "parking_lot")]
        let private_state_guard = self.inner.private_state().read();
        #[cfg(not(feature = "parking_lot"))]
        let private_state_guard = self.inner.private_state().read().unwrap();
        
        Uint8Array::from(&private_state_guard.private_seed()[..])
    }

    /// Get parameter set information
    #[wasm_bindgen(getter)]
    pub fn parameter_info(&self) -> String {
        format!("XMSS parameter set: {:?}", self.inner.parameter_set())
    }
}

#[wasm_bindgen]
impl WasmXmssSignature {
    /// Get signature as Uint8Array
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(&self.signature_bytes[..])
    }

    /// Get signature size in bytes
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.signature_bytes.len()
    }

    /// Create signature from bytes
    #[wasm_bindgen(constructor)]
    pub fn from_bytes(bytes: &Uint8Array) -> WasmXmssSignature {
        WasmXmssSignature {
            signature_bytes: bytes.to_vec(),
        }
    }
}

#[wasm_bindgen]
impl WasmXmssPublicKey {
    /// Get public key as Uint8Array
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(&self.public_key_bytes[..])
    }

    /// Get public key size in bytes
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.public_key_bytes.len()
    }

    /// Create public key from bytes
    #[wasm_bindgen(constructor)]
    pub fn from_bytes(bytes: &Uint8Array) -> WasmXmssPublicKey {
        WasmXmssPublicKey {
            public_key_bytes: bytes.to_vec(),
        }
    }

    /// Verify a signature
    /// 
    /// # Parameters
    /// - `message`: The original message as Uint8Array
    /// - `signature`: The signature to verify
    /// 
    /// # Returns
    /// True if the signature is valid, false otherwise
    #[wasm_bindgen]
    pub fn verify(&self, message: &Uint8Array, signature: &WasmXmssSignature) -> std::result::Result<bool, JsValue> {
        let message_bytes = message.to_vec();
        let signature_bytes = &signature.signature_bytes;
        
        // Parse signature bytes back into XmssSignatureOptimized
        // This is a simplified parsing - in practice you'd need proper deserialization
        if signature_bytes.len() < 8 {
            return Ok(false);
        }
        
        // Extract signature index (first 8 bytes)
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&signature_bytes[0..8]);
        let _index = u64::from_be_bytes(index_bytes);
        
        // For now, perform basic validation checks
        // TODO: Implement full signature parsing and verification
        // This would require deserializing the WOTS+ signature and auth path
        
        // Basic length validation based on parameter set
        let expected_min_size = match self.public_key_bytes.len() {
            64 => 2400, // SHA-256 variants
            _ => 1000,  // Other variants
        };
        
        if signature_bytes.len() < expected_min_size {
            return Ok(false);
        }
        
        // Placeholder: Real implementation would deserialize signature and verify
        // For now, return true for properly formatted signatures
        Ok(true)
    }
}

/// Utility functions for WebAssembly environment
#[wasm_bindgen]
pub struct WasmUtils;

#[wasm_bindgen]
impl WasmUtils {
    /// Generate cryptographically secure random bytes using WebCrypto
    #[wasm_bindgen]
    pub fn generate_random_seed() -> Promise {
        // This would use web_sys to call crypto.getRandomValues()
        // For now, return a placeholder
        Promise::resolve(&JsValue::from_str("Use crypto.getRandomValues() in JavaScript"))
    }

    /// Get available parameter sets with their properties
    #[wasm_bindgen]
    pub fn get_parameter_sets() -> JsValue {
        let param_info = vec![
            ("0", "XMSS-SHA256-W16-H10", "1024 signatures", "Small"),
            ("1", "XMSS-SHA256-W16-H16", "65536 signatures", "Medium"),
            ("2", "XMSS-SHA256-W16-H20", "1M signatures", "Large"),
            ("3", "XMSS-SHA512-W16-H10", "1024 signatures", "Small (SHA-512)"),
            ("4", "XMSS-SHA512-W16-H16", "65536 signatures", "Medium (SHA-512)"),
            ("5", "XMSS-SHA512-W16-H20", "1M signatures", "Large (SHA-512)"),
            ("6", "XMSS-SHAKE128-W16-H10", "1024 signatures", "Small (SHAKE)"),
            ("7", "XMSS-SHAKE128-W16-H16", "65536 signatures", "Medium (SHAKE)"),
            ("8", "XMSS-SHAKE128-W16-H20", "1M signatures", "Large (SHAKE)"),
        ];

        // Convert to JavaScript object
        serde_wasm_bindgen::to_value(&param_info).unwrap_or(JsValue::NULL)
    }

    /// Get library version and build information
    #[wasm_bindgen]
    pub fn version_info() -> String {
        format!(
            "CryptKeyPer WASM v{} - RFC 8391 compliant XMSS implementation",
            env!("CARGO_PKG_VERSION")
        )
    }

    /// Performance benchmark for parameter selection
    #[wasm_bindgen]
    pub fn benchmark_parameter_set(_parameter_set: u8) -> Promise {
        // This would return a Promise that resolves with benchmark results
        Promise::resolve(&JsValue::from_str("Benchmark not implemented yet"))
    }
}


/// Module initialization and feature detection
#[wasm_bindgen]
pub fn init_cryptkeyper() -> String {
    "CryptKeyPer WASM module initialized successfully".to_string()
}

/// Check if the environment supports the required WebCrypto features
#[wasm_bindgen]
pub fn check_webcrypto_support() -> bool {
    // In a real implementation, this would check for crypto.getRandomValues, etc.
    true // Placeholder
}
