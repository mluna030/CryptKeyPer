# CryptKeyPer

CryptKeyPer is a Rust-based library for post-quantum cryptographic key management, featuring a complete implementation of the **eXtended Merkle Signature Scheme (XMSS)** as specified in [RFC 8391](https://tools.ietf.org/rfc/rfc8391.txt). The library focuses on deterministic random bit generation (HMAC_DRBG), secure seed handling, and quantum-resistant digital signatures.

## Why XMSS?

XMSS is a **hash-based signature scheme** that provides **quantum-resistant** security guarantees. Unlike traditional signature schemes (RSA, ECDSA) that rely on mathematical problems vulnerable to quantum computers, XMSS security depends only on the security of cryptographic hash functions, which are believed to be quantum-resistant.

### Key Advantages of XMSS:
- **Quantum Resistance**: Secure against both classical and quantum attacks
- **Minimal Security Assumptions**: Only requires secure hash functions
- **Standardized**: IETF RFC 8391 specification ensures interoperability
- **Proven Security**: Based on well-understood cryptographic primitives
- **Long-term Security**: Suitable for applications requiring decades of security

### RFC 8391 Compliance

This implementation follows the official [IETF RFC 8391](https://tools.ietf.org/rfc/rfc8391.txt) specification, which defines:
- **WOTS+ (Winternitz One-Time Signature Plus)**: The underlying one-time signature scheme
- **Address Scheme**: Domain separation to prevent multi-target attacks  
- **XMSS Tree Construction**: Merkle tree-based key management
- **Security Parameters**: Standardized parameter sets for different security levels

**Development Status**: This is an educational/research implementation. For production use, consider established libraries like [XMSS Reference Implementation](https://github.com/XMSS/xmss-reference) or consult cryptographic experts.

## Post-Quantum Context

With the advancement of quantum computing, traditional public-key cryptography faces existential threats:
- **Shor's Algorithm** can break RSA, ECC, and DH-based systems
- **Grover's Algorithm** reduces symmetric security by half
- **Timeline Uncertainty**: Quantum computers capable of breaking current cryptography may emerge within 10-20 years

XMSS provides a **quantum-safe alternative** for digital signatures, making it crucial for:
- Long-term document signing
- Certificate authorities
- Secure communications
- Blockchain and cryptocurrency systems
- Any application requiring long-term signature verification

## Table of Contents

- [Why XMSS?](#why-xmss)
- [RFC 8391 Compliance](#rfc-8391-compliance)
- [Post-Quantum Context](#post-quantum-context)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Technical Details](#technical-details)
- [References](#references)
- [License](#license)
- [Contact](#contact)

## Installation

Follow these steps to install CryptKeyPer:

```bash
# Clone the repository
git clone https://github.com/mluna030/CryptKeyPer.git

# Navigate to the project directory
cd CryptKeyPer

# Build the project using Cargo
cargo build

# Run tests
cargo test
```

## Usage

### Basic XMSS Operations

```rust
use cryptkeyper::{Xmss, Result};

fn main() -> Result<()> {
    // Create XMSS instance with height 10 (2^10 = 1024 signatures)
    let mut xmss = Xmss::new(10)?;
    
    // Message to sign (must be exactly 32 bytes)
    let message = [0u8; 32]; // In practice, this would be a hash of your data
    
    // Sign the message
    let signature = xmss.sign(&message)?;
    
    // Verify the signature
    let is_valid = Xmss::verify(&message, &signature, &xmss.public_key)?;
    assert!(is_valid);
    
    println!("Signatures remaining: {}", xmss.remaining_signatures());
    
    Ok(())
}
```

### HMAC-DRBG for Secure Random Generation

```rust
use cryptkeyper::drbg::drbg::HmacDrbg;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with entropy
    let entropy = b"high_entropy_seed_at_least_32_bytes_long_for_security";
    let mut drbg = HmacDrbg::new(entropy, None)?;
    
    // Generate random bytes
    let random_bytes = drbg.generate(32)?;
    println!("Generated {} random bytes", random_bytes.len());
    
    Ok(())
}
```

### Mnemonic Seed Handling

```rust
use cryptkeyper::mnemonic::mnemonic::MnemonicSeed;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create seed from passphrase
    let seed = MnemonicSeed::from_passphrase("my secure passphrase", None)?;
    
    // Get 32-byte seed for cryptographic operations
    let crypto_seed = seed.to_seed();
    
    Ok(())
}
```

## Features

### Core Components
- **XMSS (eXtended Merkle Signature Scheme)**: RFC 8391 compliant post-quantum signatures
- **WOTS+ (Winternitz One-Time Signature Plus)**: Quantum-resistant one-time signatures with checksums
- **HMAC-DRBG**: NIST SP 800-90A compliant deterministic random bit generation
- **Mnemonic Seed Handling**: Secure seed derivation and management
- **Merkle Trees**: Cryptographically secure tree structures with authentication paths

### Security Features
- **Quantum Resistance**: All signature operations are quantum-safe
- **Memory Safety**: Automatic zeroization of sensitive data
- **Comprehensive Error Handling**: Robust error management throughout
- **Address Schemes**: Domain separation preventing multi-target attacks
- **Bitmask Protection**: Enhanced security for hash operations

### Implementation Highlights
- **RFC Compliance**: Follows IETF RFC 8391 specification exactly
- **Configurable Parameters**: Support for different security levels (tree heights 1-20)
- **Stateful Security**: Proper one-time signature key management
- **Cross-platform**: Pure Rust implementation with minimal dependencies

## Technical Details

### XMSS Parameters
- **Hash Function**: SHA-256 (32-byte output)
- **Winternitz Parameter**: w = 16 (optimal security/size tradeoff)
- **WOTS+ Chains**: 67 total (64 message + 3 checksum)
- **Supported Heights**: 1-20 (2 to ~1M signatures)
- **Address Length**: 32 bytes for domain separation

### Security Considerations
- Each XMSS private key can sign exactly 2^h messages (where h is the tree height)
- **Critical**: Never reuse signature indices - this breaks security completely
- Signature verification is stateless and can be performed by anyone
- Private keys should be stored securely and backed up before first use

### Performance Characteristics
- **Key Generation**: O(2^h) - scales exponentially with tree height
- **Signing**: O(h) - logarithmic in number of signatures
- **Verification**: O(h) - logarithmic verification time
- **Memory Usage**: O(2^h) for full key storage

## References

### Official Specifications
- **[RFC 8391 - XMSS: eXtended Merkle Signature Scheme](https://tools.ietf.org/rfc/rfc8391.txt)** - The official IETF specification
- **[NIST SP 800-208](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)** - Recommendation for Stateful Hash-Based Signature Schemes
- **[NIST SP 800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)** - Recommendation for Random Number Generation Using Deterministic Random Bit Generators

### Academic Papers
- **[XMSS - A Practical Forward Secure Signature Scheme based on Minimal Security Assumptions](https://eprint.iacr.org/2011/484.pdf)** - Original XMSS paper
- **[WOTS+ – Shorter Signatures for Hash-Based Signature Schemes](https://eprint.iacr.org/2017/965.pdf)** - WOTS+ improvement paper

### Additional Resources
- **[XMSS Reference Implementation](https://github.com/XMSS/xmss-reference)** - Official reference implementation in C
- **[Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)** - NIST PQC project
- **[Quantum Computing and Cryptography](https://en.wikipedia.org/wiki/Post-quantum_cryptography)** - Background on quantum threats

## License
- Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International

## Contact

For any questions or suggestions, feel free to contact me:

Michael Luna - michael.angelo.luna1@gmail.com

LinkedIn: [Michael Luna](https://www.linkedin.com/in/michael-luna6262/)

Project Link: https://github.com/mluna030/CryptKeyPer

Demo Link: [Try it out](https://mluna030.vercel.app/tools/crypto-tools)

