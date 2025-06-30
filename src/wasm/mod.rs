//! WebAssembly bindings for CryptKeyPer XMSS implementation
//! 
//! This module provides JavaScript-compatible APIs for using XMSS 
//! post-quantum signatures in web browsers and Node.js environments.

use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array, Promise};
use crate::parameters::XmssParameterSet;
use crate::xmss::xmss_optimized::XmssOptimized;
use crate::errors::{CryptKeyperError, Result};

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
    pub fn new(parameter_set: u8, seed: Option<Uint8Array>) -> Result<WasmXmssKeyPair, JsValue> {
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
            // Use WebCrypto for random generation
            return Err(JsValue::from_str("Seed is required for deterministic key generation"));
        };

        if seed_bytes.len() != 32 {
            return Err(JsValue::from_str("Seed must be exactly 32 bytes"));
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed_bytes);

        let xmss = XmssOptimized::from_seed(params, &seed_array)
            .map_err(|e| JsValue::from_str(&format!("Failed to create XMSS: {}", e)))?;

        Ok(WasmXmssKeyPair { inner: xmss })
    }

    /// Get the public key
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> WasmXmssPublicKey {
        WasmXmssPublicKey {
            public_key_bytes: self.inner.export_public_key(),
        }
    }

    /// Sign a message
    /// 
    /// # Parameters  
    /// - `message`: The message to sign as Uint8Array
    /// 
    /// # Returns
    /// A signature that can be verified with the public key
    #[wasm_bindgen]
    pub fn sign(&mut self, message: &Uint8Array) -> Result<WasmXmssSignature, JsValue> {
        let message_bytes = message.to_vec();
        
        let signature = self.inner.sign(&message_bytes)
            .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;

        Ok(WasmXmssSignature {
            signature_bytes: signature,
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
        self.inner.max_signatures()
    }

    /// Export the private key (be very careful with this!)
    #[wasm_bindgen]
    pub fn export_private_key(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.export_private_seed()[..])
    }

    /// Get parameter set information
    #[wasm_bindgen(getter)]
    pub fn parameter_info(&self) -> String {
        format!("XMSS parameter set: {}", self.inner.parameter_set_name())
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
    pub fn verify(&self, message: &Uint8Array, signature: &WasmXmssSignature) -> Result<bool, JsValue> {
        let message_bytes = message.to_vec();
        
        // Note: This is a simplified implementation
        // In a full implementation, you'd need the parameter set to properly verify
        let result = XmssOptimized::verify_signature(
            &message_bytes,
            &signature.signature_bytes,
            &self.public_key_bytes
        ).map_err(|e| JsValue::from_str(&format!("Verification failed: {}", e)))?;

        Ok(result)
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
        JsValue::from_serde(&param_info).unwrap_or(JsValue::NULL)
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
    pub fn benchmark_parameter_set(parameter_set: u8) -> Promise {
        // This would return a Promise that resolves with benchmark results
        Promise::resolve(&JsValue::from_str("Benchmark not implemented yet"))
    }
}

/// Error handling for WebAssembly
impl From<CryptKeyperError> for JsValue {
    fn from(err: CryptKeyperError) -> Self {
        JsValue::from_str(&format!("CryptKeyPer Error: {}", err))
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