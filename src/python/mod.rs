//! Python bindings for CryptKeyPer using PyO3
//! 
//! This module provides Python-friendly APIs for XMSS post-quantum signatures

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use std::collections::HashMap;

use crate::parameters::XmssParameterSet;
use crate::xmss::xmss_optimized::XmssOptimized;
use crate::errors::{CryptKeyperError, Result};

/// Python wrapper for XMSS key pair
#[pyclass(name = "XmssKeyPair")]
pub struct PyXmssKeyPair {
    inner: XmssOptimized,
    parameter_set: XmssParameterSet,
}

/// Python wrapper for XMSS signature
#[pyclass(name = "XmssSignature")]
pub struct PyXmssSignature {
    signature_bytes: Vec<u8>,
}

/// Python wrapper for XMSS public key
#[pyclass(name = "XmssPublicKey")]
pub struct PyXmssPublicKey {
    public_key_bytes: Vec<u8>,
}

#[pymethods]
impl PyXmssKeyPair {
    /// Create a new XMSS key pair
    /// 
    /// Args:
    ///     parameter_set (str): Parameter set name (e.g., "XMSS-SHA256-W16-H10")
    ///     seed (bytes, optional): 32-byte seed for deterministic key generation
    /// 
    /// Returns:
    ///     XmssKeyPair: New key pair instance
    /// 
    /// Example:
    ///     >>> import cryptkeyper
    ///     >>> keypair = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10")
    ///     >>> print(f"Remaining signatures: {keypair.remaining_signatures}")
    #[new]
    #[pyo3(signature = (parameter_set, seed = None))]
    fn new(parameter_set: &str, seed: Option<&[u8]>) -> PyResult<Self> {
        let params = parse_parameter_set(parameter_set)?;
        
        let xmss = if let Some(seed_bytes) = seed {
            if seed_bytes.len() != 32 {
                return Err(PyValueError::new_err("Seed must be exactly 32 bytes"));
            }
            let mut seed_array = [0u8; 32];
            seed_array.copy_from_slice(seed_bytes);
            XmssOptimized::from_seed(params, &seed_array)
        } else {
            XmssOptimized::new(params)
        };
        
        match xmss {
            Ok(xmss_instance) => Ok(Self {
                inner: xmss_instance,
                parameter_set: params,
            }),
            Err(e) => Err(PyRuntimeError::new_err(format!("Failed to create XMSS: {}", e))),
        }
    }
    
    /// Get the public key
    /// 
    /// Returns:
    ///     XmssPublicKey: The public key for signature verification
    #[getter]
    fn public_key(&self) -> PyXmssPublicKey {
        PyXmssPublicKey {
            public_key_bytes: self.inner.export_public_key(),
        }
    }
    
    /// Sign a message
    /// 
    /// Args:
    ///     message (bytes): The message to sign
    /// 
    /// Returns:
    ///     XmssSignature: The signature
    /// 
    /// Raises:
    ///     RuntimeError: If signing fails or no signatures remain
    /// 
    /// Example:
    ///     >>> signature = keypair.sign(b"Hello, post-quantum world!")
    ///     >>> print(f"Signature size: {len(signature.bytes)} bytes")
    fn sign(&mut self, message: &[u8]) -> PyResult<PyXmssSignature> {
        match self.inner.sign(message) {
            Ok(signature_bytes) => Ok(PyXmssSignature { signature_bytes }),
            Err(e) => Err(PyRuntimeError::new_err(format!("Signing failed: {}", e))),
        }
    }
    
    /// Get the number of remaining signatures
    /// 
    /// Returns:
    ///     int: Number of signatures that can still be created
    #[getter]
    fn remaining_signatures(&self) -> u64 {
        self.inner.remaining_signatures()
    }
    
    /// Get the maximum number of signatures for this parameter set
    /// 
    /// Returns:
    ///     int: Maximum signatures for this parameter set
    #[getter]
    fn max_signatures(&self) -> u64 {
        self.inner.max_signatures()
    }
    
    /// Get parameter set information
    /// 
    /// Returns:
    ///     str: Parameter set name and details
    #[getter]
    fn parameter_info(&self) -> String {
        format!("XMSS parameter set: {}", self.inner.parameter_set_name())
    }
    
    /// Export the private seed (use with extreme caution!)
    /// 
    /// Returns:
    ///     bytes: 32-byte private seed
    /// 
    /// Warning:
    ///     This exposes the private key material. Only use for backup/recovery.
    fn export_private_seed(&self) -> Vec<u8> {
        self.inner.export_private_seed().to_vec()
    }
    
    /// Save the key pair state to a file
    /// 
    /// Args:
    ///     filename (str): Path to save the encrypted state
    ///     password (str): Password to encrypt the state
    /// 
    /// Example:
    ///     >>> keypair.save_state("my_xmss_key.enc", "secure_password_123")
    fn save_state(&self, filename: &str, password: &str) -> PyResult<()> {
        // In a real implementation, this would use the SecureStateManager
        // For now, just demonstrate the API
        Err(PyRuntimeError::new_err("State saving not yet implemented"))
    }
    
    /// Load key pair state from a file
    /// 
    /// Args:
    ///     filename (str): Path to the encrypted state file
    ///     password (str): Password to decrypt the state
    /// 
    /// Returns:
    ///     XmssKeyPair: Restored key pair
    #[staticmethod]
    fn load_state(filename: &str, password: &str) -> PyResult<Self> {
        // In a real implementation, this would use the SecureStateManager
        Err(PyRuntimeError::new_err("State loading not yet implemented"))
    }
    
    /// Python string representation
    fn __repr__(&self) -> String {
        format!(
            "XmssKeyPair(parameter_set='{}', remaining_signatures={})",
            self.parameter_info(),
            self.remaining_signatures()
        )
    }
}

#[pymethods]
impl PyXmssSignature {
    /// Get signature as bytes
    /// 
    /// Returns:
    ///     bytes: The signature data
    #[getter]
    fn bytes(&self) -> &[u8] {
        &self.signature_bytes
    }
    
    /// Get signature size in bytes
    /// 
    /// Returns:
    ///     int: Size of the signature in bytes
    #[getter]
    fn size(&self) -> usize {
        self.signature_bytes.len()
    }
    
    /// Create signature from bytes
    /// 
    /// Args:
    ///     data (bytes): Signature bytes
    /// 
    /// Returns:
    ///     XmssSignature: Signature instance
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> Self {
        Self {
            signature_bytes: data.to_vec(),
        }
    }
    
    /// Python string representation
    fn __repr__(&self) -> String {
        format!("XmssSignature(size={} bytes)", self.signature_bytes.len())
    }
    
    /// Python length support
    fn __len__(&self) -> usize {
        self.signature_bytes.len()
    }
}

#[pymethods]
impl PyXmssPublicKey {
    /// Get public key as bytes
    /// 
    /// Returns:
    ///     bytes: The public key data
    #[getter]
    fn bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }
    
    /// Get public key size in bytes
    /// 
    /// Returns:
    ///     int: Size of the public key in bytes
    #[getter]
    fn size(&self) -> usize {
        self.public_key_bytes.len()
    }
    
    /// Create public key from bytes
    /// 
    /// Args:
    ///     data (bytes): Public key bytes
    /// 
    /// Returns:
    ///     XmssPublicKey: Public key instance
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> Self {
        Self {
            public_key_bytes: data.to_vec(),
        }
    }
    
    /// Verify a signature
    /// 
    /// Args:
    ///     message (bytes): The original message
    ///     signature (XmssSignature): The signature to verify
    /// 
    /// Returns:
    ///     bool: True if the signature is valid
    /// 
    /// Example:
    ///     >>> is_valid = public_key.verify(b"message", signature)
    ///     >>> print(f"Signature valid: {is_valid}")
    fn verify(&self, message: &[u8], signature: &PyXmssSignature) -> PyResult<bool> {
        match XmssOptimized::verify_signature(message, &signature.signature_bytes, &self.public_key_bytes) {
            Ok(valid) => Ok(valid),
            Err(e) => Err(PyRuntimeError::new_err(format!("Verification failed: {}", e))),
        }
    }
    
    /// Python string representation
    fn __repr__(&self) -> String {
        format!("XmssPublicKey(size={} bytes)", self.public_key_bytes.len())
    }
    
    /// Python length support
    fn __len__(&self) -> usize {
        self.public_key_bytes.len()
    }
}

/// Utility functions for the Python module
#[pyclass(name = "CryptKeyperUtils")]
pub struct PyCryptKeyperUtils;

#[pymethods]
impl PyCryptKeyperUtils {
    /// Get available parameter sets
    /// 
    /// Returns:
    ///     dict: Dictionary of parameter set information
    /// 
    /// Example:
    ///     >>> params = CryptKeyperUtils.get_parameter_sets()
    ///     >>> for name, info in params.items():
    ///     ...     print(f"{name}: {info['signatures']} signatures")
    #[staticmethod]
    fn get_parameter_sets(py: Python) -> PyResult<PyObject> {
        let params = PyDict::new(py);
        
        let param_info = vec![
            ("XMSS-SHA256-W16-H10", "1,024 signatures", "Small (IoT/embedded)"),
            ("XMSS-SHA256-W16-H16", "65,536 signatures", "Medium (general use)"),
            ("XMSS-SHA256-W16-H20", "1,048,576 signatures", "Large (long-term)"),
            ("XMSS-SHA512-W16-H10", "1,024 signatures", "Small (high security)"),
            ("XMSS-SHA512-W16-H16", "65,536 signatures", "Medium (high security)"),
            ("XMSS-SHA512-W16-H20", "1,048,576 signatures", "Large (high security)"),
            ("XMSS-SHAKE128-W16-H10", "1,024 signatures", "Small (SHAKE variant)"),
            ("XMSS-SHAKE128-W16-H16", "65,536 signatures", "Medium (SHAKE variant)"),
            ("XMSS-SHAKE128-W16-H20", "1,048,576 signatures", "Large (SHAKE variant)"),
        ];
        
        for (name, signatures, description) in param_info {
            let info = PyDict::new(py);
            info.set_item("signatures", signatures)?;
            info.set_item("description", description)?;
            info.set_item("quantum_safe", true)?;
            params.set_item(name, info)?;
        }
        
        Ok(params.into())
    }
    
    /// Get library version information
    /// 
    /// Returns:
    ///     str: Version and build information
    #[staticmethod]
    fn version_info() -> String {
        format!(
            "CryptKeyPer Python v{} - RFC 8391 compliant XMSS implementation",
            env!("CARGO_PKG_VERSION")
        )
    }
    
    /// Generate cryptographically secure random seed
    /// 
    /// Returns:
    ///     bytes: 32 bytes of cryptographically secure random data
    /// 
    /// Example:
    ///     >>> seed = CryptKeyperUtils.generate_random_seed()
    ///     >>> keypair = XmssKeyPair("XMSS-SHA256-W16-H10", seed)
    #[staticmethod]
    fn generate_random_seed(py: Python) -> PyResult<PyObject> {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Ok(PyBytes::new(py, &seed).into())
    }
    
    /// Estimate signature sizes for different parameter sets
    /// 
    /// Returns:
    ///     dict: Dictionary mapping parameter sets to signature sizes
    #[staticmethod]
    fn estimate_signature_sizes(py: Python) -> PyResult<PyObject> {
        let sizes = PyDict::new(py);
        
        // Approximate XMSS signature sizes (in bytes)
        let size_estimates = vec![
            ("XMSS-SHA256-W16-H10", 2500),
            ("XMSS-SHA256-W16-H16", 2800),
            ("XMSS-SHA256-W16-H20", 3100),
            ("XMSS-SHA512-W16-H10", 4900),
            ("XMSS-SHA512-W16-H16", 5500),
            ("XMSS-SHA512-W16-H20", 6100),
            ("XMSS-SHAKE128-W16-H10", 2500),
            ("XMSS-SHAKE128-W16-H16", 2800),
            ("XMSS-SHAKE128-W16-H20", 3100),
        ];
        
        for (name, size) in size_estimates {
            sizes.set_item(name, size)?;
        }
        
        Ok(sizes.into())
    }
    
    /// Benchmark a parameter set (simulated results)
    /// 
    /// Args:
    ///     parameter_set (str): Parameter set to benchmark
    /// 
    /// Returns:
    ///     dict: Benchmark results
    #[staticmethod]
    fn benchmark_parameter_set(py: Python, parameter_set: &str) -> PyResult<PyObject> {
        let _params = parse_parameter_set(parameter_set)?;
        
        let results = PyDict::new(py);
        
        // Simulated benchmark results (would be real timings in production)
        results.set_item("keygen_time_ms", 50.0)?;
        results.set_item("sign_time_ms", 25.0)?;
        results.set_item("verify_time_ms", 10.0)?;
        results.set_item("signature_size_bytes", 2800)?;
        results.set_item("public_key_size_bytes", 64)?;
        results.set_item("note", "Simulated results - run actual benchmarks for real timings")?;
        
        Ok(results.into())
    }
}

/// High-level convenience functions
#[pyfunction]
/// Quick sign - create a key pair and sign in one call
/// 
/// Args:
///     message (bytes): Message to sign
///     parameter_set (str, optional): Parameter set to use
///     seed (bytes, optional): Seed for deterministic key generation
/// 
/// Returns:
///     tuple: (signature_bytes, public_key_bytes, remaining_signatures)
/// 
/// Example:
///     >>> sig, pubkey, remaining = quick_sign(b"Hello world!")
///     >>> print(f"Signed! {remaining} signatures remaining")
#[pyo3(signature = (message, parameter_set = "XMSS-SHA256-W16-H10", seed = None))]
fn quick_sign(py: Python, message: &[u8], parameter_set: &str, seed: Option<&[u8]>) -> PyResult<PyObject> {
    let mut keypair = PyXmssKeyPair::new(parameter_set, seed)?;
    let signature = keypair.sign(message)?;
    let public_key = keypair.public_key();
    let remaining = keypair.remaining_signatures();
    
    Ok((
        PyBytes::new(py, signature.bytes()),
        PyBytes::new(py, public_key.bytes()),
        remaining,
    ).into())
}

#[pyfunction]
/// Quick verify - verify a signature without creating objects
/// 
/// Args:
///     message (bytes): Original message
///     signature_bytes (bytes): Signature to verify
///     public_key_bytes (bytes): Public key for verification
/// 
/// Returns:
///     bool: True if signature is valid
/// 
/// Example:
///     >>> is_valid = quick_verify(b"Hello world!", sig_bytes, pubkey_bytes)
///     >>> print(f"Valid: {is_valid}")
fn quick_verify(message: &[u8], signature_bytes: &[u8], public_key_bytes: &[u8]) -> PyResult<bool> {
    match XmssOptimized::verify_signature(message, signature_bytes, public_key_bytes) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(PyRuntimeError::new_err(format!("Verification failed: {}", e))),
    }
}

/// Parse parameter set string to enum
fn parse_parameter_set(param_str: &str) -> PyResult<XmssParameterSet> {
    match param_str {
        "XMSS-SHA256-W16-H10" => Ok(XmssParameterSet::XmssSha256W16H10),
        "XMSS-SHA256-W16-H16" => Ok(XmssParameterSet::XmssSha256W16H16),
        "XMSS-SHA256-W16-H20" => Ok(XmssParameterSet::XmssSha256W16H20),
        "XMSS-SHA512-W16-H10" => Ok(XmssParameterSet::XmssSha512W16H10),
        "XMSS-SHA512-W16-H16" => Ok(XmssParameterSet::XmssSha512W16H16),
        "XMSS-SHA512-W16-H20" => Ok(XmssParameterSet::XmssSha512W16H20),
        "XMSS-SHAKE128-W16-H10" => Ok(XmssParameterSet::XmssShake128W16H10),
        "XMSS-SHAKE128-W16-H16" => Ok(XmssParameterSet::XmssShake128W16H16),
        "XMSS-SHAKE128-W16-H20" => Ok(XmssParameterSet::XmssShake128W16H20),
        _ => Err(PyValueError::new_err(format!("Unknown parameter set: {}", param_str))),
    }
}

/// Convert CryptKeyperError to Python exception
impl From<CryptKeyperError> for PyErr {
    fn from(err: CryptKeyperError) -> Self {
        PyRuntimeError::new_err(format!("CryptKeyPer error: {}", err))
    }
}

/// Python module definition
#[pymodule]
fn cryptkeyper(_py: Python, m: &PyModule) -> PyResult<()> {
    // Classes
    m.add_class::<PyXmssKeyPair>()?;
    m.add_class::<PyXmssSignature>()?;
    m.add_class::<PyXmssPublicKey>()?;
    m.add_class::<PyCryptKeyperUtils>()?;
    
    // Functions
    m.add_function(wrap_pyfunction!(quick_sign, m)?)?;
    m.add_function(wrap_pyfunction!(quick_verify, m)?)?;
    
    // Module metadata
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__doc__", "CryptKeyPer: RFC 8391 compliant XMSS post-quantum signatures")?;
    
    Ok(())
}