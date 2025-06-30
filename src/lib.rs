//! # CryptKeyPer
//!
//! A Rust library implementing the eXtended Merkle Signature Scheme (XMSS) as specified in 
//! [RFC 8391](https://tools.ietf.org/rfc/rfc8391.txt). This library provides quantum-resistant
//! digital signatures suitable for post-quantum cryptography applications.
//!
//! ## Features
//!
//! - **RFC 8391 Compliant**: Full implementation of the IETF XMSS specification
//! - **Quantum Resistant**: Security based only on hash function assumptions
//! - **WOTS+ Signatures**: Winternitz One-Time Signatures with checksums
//! - **Secure DRBG**: HMAC-DRBG following NIST SP 800-90A
//! - **Memory Safety**: Automatic zeroization of sensitive data
//!
//! ## Quick Start
//!
//! ### Basic XMSS Usage
//! ```rust
//! use cryptkeyper::{XmssOptimized, XmssParameterSet, Result};
//!
//! fn main() -> Result<()> {
//!     // Create optimized XMSS instance
//!     let xmss = XmssOptimized::new(XmssParameterSet::XmssSha256W16H10)?;
//!     
//!     // Sign a message
//!     let message = b"Hello, post-quantum world!";
//!     let signature = xmss.sign(message)?;
//!     
//!     // Verify the signature
//!     let is_valid = XmssOptimized::verify(message, &signature, &xmss.public_key)?;
//!     assert!(is_valid);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### Multi-Tree XMSS^MT for Unlimited Signatures
//! ```rust
//! use cryptkeyper::{XmssMt, XmssMtParameterSet, Result};
//!
//! fn main() -> Result<()> {
//!     // Create XMSS^MT instance (virtually unlimited signatures)
//!     let xmss_mt = XmssMt::new(XmssMtParameterSet::XmssMtSha256W16H20D2)?;
//!     
//!     // Sign multiple messages
//!     for i in 0..1000 {
//!         let message = format!("Message {}", i);
//!         let signature = xmss_mt.sign(message.as_bytes())?;
//!         
//!         let is_valid = XmssMt::verify(
//!             message.as_bytes(), 
//!             &signature, 
//!             &xmss_mt.public_key
//!         )?;
//!         assert!(is_valid);
//!     }
//!     
//!     println!("Remaining signatures: {}", xmss_mt.remaining_signatures());
//!     Ok(())
//! }
//! ```
//!
//! ### Secure State Management
//! ```rust
//! use cryptkeyper::{SecureStateManager, Result};
//! use std::path::Path;
//!
//! fn main() -> Result<()> {
//!     // Create secure state manager
//!     let state_manager = SecureStateManager::new(
//!         Path::new("xmss_state.enc"),
//!         Path::new("backups/"),
//!         10, // Keep 10 backups
//!     )?;
//!     
//!     // Initialize with password
//!     state_manager.initialize_with_password("secure_password_123")?;
//!     
//!     // Store and load state securely
//!     let private_seed = [42u8; 32];
//!     state_manager.store_state(&private_seed, 100, 1024)?;
//!     
//!     let (loaded_seed, index, max_sigs) = state_manager.load_state()?;
//!     assert_eq!(loaded_seed, private_seed);
//!     assert_eq!(index, 100);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Security Notice
//!
//! **⚠️ Educational Implementation**: This library is intended for educational and research 
//! purposes. For production applications requiring quantum-resistant signatures, please consult
//! cryptographic experts and consider using established implementations.
//!
//! ## References
//!
//! - [RFC 8391 - XMSS: eXtended Merkle Signature Scheme](https://tools.ietf.org/rfc/rfc8391.txt)
//! - [NIST SP 800-208 - Hash-Based Signatures](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)

pub mod errors;
pub mod hash_function;
pub mod hash_traits;
pub mod hash_optimized;
pub mod parameters;
pub mod state_management;
pub mod drbg;
pub mod random_key_generator;
pub mod mnemonic;
pub mod xmss;
pub mod pqc_graveyard;
pub mod hardware;
pub mod mobile;

// WebAssembly bindings
#[cfg(feature = "wasm")]
pub mod wasm;

pub use errors::{CryptKeyperError, Result};
pub use parameters::{XmssParameterSet, XmssMtParameterSet, WotsParameters};
pub use hash_traits::{HashFunction, Sha256HashFunction, Sha512HashFunction, Shake128HashFunction};
pub use state_management::{SecureStateManager, BackupInfo};

// Original implementations
pub use xmss::xmss::{Xmss, XmssSignature, XmssPublicKey};

// Optimized implementations
pub use xmss::xmss_optimized::{XmssOptimized, XmssSignatureOptimized, XmssPublicKeyOptimized};
pub use xmss::wots_optimized::WotsPlusOptimized;

// Multi-tree implementation
pub use xmss::xmss_mt::{XmssMt, XmssMtSignature, XmssMtPublicKey, XmssMtStatistics};

pub fn add(left: usize, right: usize) -> usize 
{
    left + right
}
pub fn create_xmss(height: u32) -> Result<xmss::xmss::Xmss> 
{
    xmss::xmss::Xmss::new(height)
}

#[cfg(test)]
mod tests 
{
    use super::*;

    #[test]
    fn test_add() 
    {
        let result = add(2, 2);
        assert_eq!(result, 4, "Expected 2 + 2 to equal 4");
    }

    #[test]
    fn test_create_xmss() 
    {
        let xmss_result = create_xmss(4); // 2^4 = 16 signatures
        assert!(xmss_result.is_ok(), "Expected XMSS creation to succeed, but it failed.");
    }
}