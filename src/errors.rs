use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptKeyperError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    
    #[error("Invalid message length: expected {expected}, got {actual}")]
    InvalidMessageLength { expected: usize, actual: usize },
    
    #[error("No more signatures available")]
    NoMoreSignatures,
    
    #[error("Invalid signature index: {0}")]
    InvalidSignatureIndex(usize),
    
    #[error("Invalid index: {0}")]
    InvalidIndex(String),
    
    #[error("Hash function error: {0}")]
    HashError(String),
    
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
    
    #[error("DRBG error: {0}")]
    DrbgError(String),
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Authentication path verification failed")]
    AuthPathVerificationFailed,
    
    #[error("Hardware acceleration error: {0}")]
    HardwareError(String),
    
    #[error("Memory allocation error: {0}")]
    MemoryError(String),
    
    #[error("Input validation failed: {0}")]
    ValidationError(String),
    
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Insufficient memory: {0}")]
    InsufficientMemory(String),
}

pub type Result<T> = std::result::Result<T, CryptKeyperError>;