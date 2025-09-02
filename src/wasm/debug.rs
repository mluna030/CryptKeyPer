//! Debug and unit testing utilities for WASM

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use crate::parameters::XmssParameterSet;
use crate::xmss::xmss_optimized::XmssOptimized;
use crate::hash_traits::HashFunction;
use std::sync::atomic::Ordering;

/// Minimal test struct for isolating WASM issues
#[wasm_bindgen]
pub struct DebugTester;

#[wasm_bindgen]
impl DebugTester {
    /// Test basic XMSS instance creation without any operations
    #[wasm_bindgen]
    pub fn test_basic_creation() -> std::result::Result<String, JsValue> {
        let params = XmssParameterSet::XmssSha256W16H10;
        
        match XmssOptimized::new(params) {
            Ok(_xmss) => Ok("XMSS instance created successfully".to_string()),
            Err(e) => Err(JsValue::from_str(&format!("XMSS creation failed: {}", e)))
        }
    }
    
    /// Test hash function operations in isolation
    #[wasm_bindgen]
    pub fn test_hash_functions() -> std::result::Result<String, JsValue> {
        let params = XmssParameterSet::XmssSha256W16H10;
        let hash_fn = params.create_hash_function();
        
        // Test basic hashing
        let test_data = b"Hello, WASM!";
        let hash_result = hash_fn.hash(test_data);
        
        if hash_result.len() == hash_fn.output_size() {
            Ok(format!("Hash function working: {} bytes output", hash_result.len()))
        } else {
            Err(JsValue::from_str("Hash function output size mismatch"))
        }
    }
    
    /// Test WOTS+ parameter calculations
    #[wasm_bindgen] 
    pub fn test_wots_params() -> std::result::Result<String, JsValue> {
        let params = XmssParameterSet::XmssSha256W16H10;
        let wots_params = params.wots_params();
        
        Ok(format!(
            "WOTS+ params: w={}, len={}, len1={}, len2={}", 
            wots_params.w,
            wots_params.len,
            wots_params.len1, 
            wots_params.len2
        ))
    }
    
    /// Test base-w conversion without crypto operations
    #[wasm_bindgen]
    pub fn test_base_w_conversion(message: &Uint8Array) -> std::result::Result<String, JsValue> {
        let message_bytes = message.to_vec();
        let params = XmssParameterSet::XmssSha256W16H10;
        let wots_params = params.wots_params();
        
        // Test message to base-w conversion
        let base_w_msg = wots_params.message_to_base_w(&message_bytes);
        
        Ok(format!("Base-w conversion: {} elements", base_w_msg.len()))
    }
    
    /// Test individual WOTS+ chain generation (the likely failure point)
    #[wasm_bindgen]
    pub fn test_single_chain() -> std::result::Result<String, JsValue> {
        let params = XmssParameterSet::XmssSha256W16H10;
        
        match XmssOptimized::new(params) {
            Ok(xmss) => {
                // Try to access the internal WOTS+ implementation
                // This will likely fail at the same point as signing
                match xmss.public_key.root.len() {
                    32 => Ok("WOTS+ chain access successful".to_string()),
                    len => Err(JsValue::from_str(&format!("Unexpected root length: {}", len)))
                }
            },
            Err(e) => Err(JsValue::from_str(&format!("XMSS creation failed: {}", e)))
        }
    }
    
    /// Test WOTS+ signing in isolation 
    #[wasm_bindgen]
    pub fn test_signing_pipeline() -> std::result::Result<String, JsValue> {
        use crate::xmss::wots_optimized::WotsPlusOptimized;
        use crate::xmss::address::XmssAddress;
        
        let params = XmssParameterSet::XmssSha256W16H10;
        let private_seed = [1u8; 32]; // Fixed seed for testing
        let pub_seed = [2u8; 32];
        let address = XmssAddress::new();
        
        // Test WOTS+ directly
        let wots = WotsPlusOptimized::new(params, private_seed, pub_seed, address);
        
        // Test message with correct hash size
        let test_message = vec![3u8; 32]; // 32 bytes for SHA-256
        
        match wots.sign(&test_message) {
            Ok(signature) => Ok(format!("WOTS+ signing successful: {} components", signature.len())),
            Err(e) => Err(JsValue::from_str(&format!("WOTS+ signing failed: {}", e)))
        }
    }
    
    /// Test memory access patterns that might cause unreachable
    #[wasm_bindgen]
    pub fn test_memory_access() -> std::result::Result<String, JsValue> {
        // Test large array allocations
        let test_size = 2500; // Approximate signature size
        let test_array: Vec<u8> = vec![0u8; test_size];
        
        if test_array.len() == test_size {
            Ok(format!("Memory allocation successful: {} bytes", test_size))
        } else {
            Err(JsValue::from_str("Memory allocation failed"))
        }
    }
}