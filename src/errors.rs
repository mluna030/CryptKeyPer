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
}

pub type Result<T> = std::result::Result<T, CryptKeyperError>;