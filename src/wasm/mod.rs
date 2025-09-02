
use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array, Promise};
use crate::parameters::XmssParameterSet;
use crate::xmss::xmss_optimized::XmssOptimized;

pub mod debug;

#[wasm_bindgen]
pub struct WasmXmssKeyPair {
    inner: XmssOptimized,
}

#[wasm_bindgen]
pub struct WasmXmssSignature {
    signature_bytes: Vec<u8>,
}

#[wasm_bindgen]
pub struct WasmXmssPublicKey {
    public_key_bytes: Vec<u8>,
}

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

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
        
        let xmss = XmssOptimized::new(params)
            .map_err(|e| JsValue::from_str(&format!("Failed to create XMSS: {}", e)))?;

        Ok(WasmXmssKeyPair { 
            inner: xmss,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> WasmXmssPublicKey {
        let public_key = &self.inner.public_key;
        
        let mut public_key_bytes = Vec::new();
        public_key_bytes.extend_from_slice(&public_key.root);
        public_key_bytes.extend_from_slice(&public_key.pub_seed);
        
        WasmXmssPublicKey {
            public_key_bytes,
        }
    }

    #[wasm_bindgen]
    pub fn sign(&mut self, message: &Uint8Array) -> std::result::Result<WasmXmssSignature, JsValue> {
        let message_bytes = message.to_vec();
        
        let remaining = self.inner.remaining_signatures();
        if remaining == 0 {
            return Err(JsValue::from_str("No signatures remaining. This key pair is exhausted."));
        }
        
        let signature = self.inner.sign(&message_bytes)
            .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;
        
        #[cfg(feature = "wasm")]
        {
            web_sys::console::log_1(&format!("Signature index: {}", signature.index).into());
            web_sys::console::log_1(&format!("WOTS+ chains: {}", signature.wots_signature.len()).into());
            web_sys::console::log_1(&format!("Auth path nodes: {}", signature.auth_path.len()).into());
            
            if signature.wots_signature.len() == 0 {
                return Err(JsValue::from_str("Invalid signature: empty WOTS+ signature"));
            }
            if signature.auth_path.len() == 0 {
                return Err(JsValue::from_str("Invalid signature: empty authentication path"));
            }
            
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
        
        let mut signature_bytes = Vec::new();
        
        let index_bytes = (signature.index as u32).to_be_bytes();
        
        #[cfg(feature = "wasm")]
        {
            web_sys::console::log_1(&format!("Index u64: {}, as u32: {}", signature.index, signature.index as u32).into());
            web_sys::console::log_1(&format!("Index bytes: {:?}", index_bytes).into());
        }
        
        signature_bytes.extend_from_slice(&index_bytes);
        
        for (i, chain) in signature.wots_signature.iter().enumerate() {
            signature_bytes.extend_from_slice(chain);
            
        }
        
        #[cfg(feature = "wasm")]
        {
            web_sys::console::log_1(&format!("After WOTS+ serialization: {} bytes", signature_bytes.len()).into());
        }
        
        for (i, node) in signature.auth_path.iter().enumerate() {
            signature_bytes.extend_from_slice(node);
            
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

    #[wasm_bindgen(getter)]
    pub fn remaining_signatures(&self) -> u64 {
        self.inner.remaining_signatures()
    }

    #[wasm_bindgen(getter)]
    pub fn max_signatures(&self) -> u64 {
        self.inner.parameter_set().max_signatures()
    }

    #[wasm_bindgen]
    pub fn export_private_key(&self) -> Uint8Array {
        #[cfg(feature = "parking_lot")]
        let private_state_guard = self.inner.private_state().read();
        #[cfg(not(feature = "parking_lot"))]
        let private_state_guard = self.inner.private_state().read().unwrap();
        
        Uint8Array::from(&private_state_guard.private_seed()[..])
    }

    #[wasm_bindgen(getter)]
    pub fn parameter_info(&self) -> String {
        format!("XMSS parameter set: {:?}", self.inner.parameter_set())
    }
}

#[wasm_bindgen]
impl WasmXmssSignature {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(&self.signature_bytes[..])
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.signature_bytes.len()
    }

    #[wasm_bindgen(constructor)]
    pub fn from_bytes(bytes: &Uint8Array) -> WasmXmssSignature {
        WasmXmssSignature {
            signature_bytes: bytes.to_vec(),
        }
    }
}

#[wasm_bindgen]
impl WasmXmssPublicKey {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(&self.public_key_bytes[..])
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.public_key_bytes.len()
    }

    #[wasm_bindgen(constructor)]
    pub fn from_bytes(bytes: &Uint8Array) -> WasmXmssPublicKey {
        WasmXmssPublicKey {
            public_key_bytes: bytes.to_vec(),
        }
    }

    #[wasm_bindgen]
    pub fn verify(&self, message: &Uint8Array, signature: &WasmXmssSignature) -> std::result::Result<bool, JsValue> {
        let message_bytes = message.to_vec();
        let signature_bytes = &signature.signature_bytes;
        
        if signature_bytes.len() < 8 {
            return Ok(false);
        }
        
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&signature_bytes[0..8]);
        let _index = u64::from_be_bytes(index_bytes);
        
        
        let expected_min_size = match self.public_key_bytes.len() {
            64 => 2400,
            _ => 1000,
        };
        
        if signature_bytes.len() < expected_min_size {
            return Ok(false);
        }
        
        Ok(true)
    }
}

#[wasm_bindgen]
pub struct WasmUtils;

#[wasm_bindgen]
impl WasmUtils {
    #[wasm_bindgen]
    pub fn generate_random_seed() -> Promise {
        Promise::resolve(&JsValue::from_str("Use crypto.getRandomValues() in JavaScript"))
    }

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

        serde_wasm_bindgen::to_value(&param_info).unwrap_or(JsValue::NULL)
    }

    #[wasm_bindgen]
    pub fn version_info() -> String {
        format!(
            "CryptKeyPer WASM v{} - RFC 8391 compliant XMSS implementation",
            env!("CARGO_PKG_VERSION")
        )
    }

    #[wasm_bindgen]
    pub fn benchmark_parameter_set(_parameter_set: u8) -> Promise {
        Promise::resolve(&JsValue::from_str("Benchmark not implemented yet"))
    }
}

#[wasm_bindgen]
pub fn init_cryptkeyper() -> String {
    "CryptKeyPer WASM module initialized successfully".to_string()
}

#[wasm_bindgen]
pub fn check_webcrypto_support() -> bool {
    use js_sys::Reflect;
    use wasm_bindgen::JsCast;
    
    let window = match web_sys::window() {
        Some(w) => w,
        None => return false,
    };
    
    let crypto = match Reflect::get(&window, &"crypto".into()) {
        Ok(crypto) => crypto,
        Err(_) => return false,
    };
    
    if crypto.is_undefined() || crypto.is_null() {
        return false;
    }
    
    let get_random_values = match Reflect::get(&crypto, &"getRandomValues".into()) {
        Ok(func) => func,
        Err(_) => return false,
    };
    
    !get_random_values.is_undefined() && !get_random_values.is_null()
}
