# CryptKeyper API Documentation

CryptKeyper is a robust, cross-platform cryptographic library designed for secure key management and post-quantum cryptographic (PQC) operations. It provides implementations of stateful hash-based signature schemes, specifically XMSS (eXtended Merkle Signature Scheme), optimized for various environments including mobile and hardware-accelerated platforms.

## 1. Core Concepts

### 1.1 XMSS (eXtended Merkle Signature Scheme)
XMSS is a hash-based signature scheme that provides strong security guarantees against quantum computer attacks. It is a stateful scheme, meaning the signer must maintain a state (e.g., the index of the last used signature) to ensure security.

- **One-Time Signatures (WOTS+):** XMSS builds upon WOTS+ (Winternitz One-Time Signature Plus), a one-time signature scheme. Each WOTS+ key pair can only be used to sign a single message securely.
- **Merkle Tree:** To overcome the one-time nature of WOTS+, XMSS uses a Merkle tree. The leaves of the Merkle tree are the public keys of many WOTS+ key pairs. The root of the Merkle tree serves as the single public key for the entire XMSS scheme.
- **Statefulness:** The signer must keep track of which WOTS+ key pair has been used to prevent reuse, which would compromise security.

### 1.2 XMSS^MT (Multi-Tree XMSS)
XMSS^MT extends XMSS to support a virtually unlimited number of signatures by organizing multiple XMSS trees into a larger tree structure. This addresses the limitation of a fixed, maximum number of signatures in a single XMSS tree.

### 1.3 Hardware Acceleration & Optimizations
CryptKeyper is designed with performance in mind, incorporating:
- **ARM NEON:** Optimized implementations for ARM processors commonly found in mobile devices.
- **OpenCL:** Support for GPU acceleration via OpenCL for parallel cryptographic operations.
- **Memory Optimization:** Techniques for efficient memory usage, crucial for resource-constrained environments.
- **Power Management:** Features to adapt cryptographic operations based on device power state and thermal conditions.

## 2. Rust API

The core CryptKeyper library is written in Rust, providing a safe, high-performance, and memory-efficient foundation.

### 2.1 Installation
Add `cryptkeyper` to your `Cargo.toml`:
```toml
[dependencies]
cryptkeyper = "0.1.0"
```
To enable OpenCL or NEON features, specify them:
```toml
[dependencies]
cryptkeyper = { version = "0.1.0", features = ["opencl", "arm_neon"] }
```

### 2.2 Key Modules

- `xmss`: Contains the core XMSS and XMSS^MT implementations.
- `parameters`: Defines the XMSS and XMSS^MT parameter sets.
- `random_key_generator`: Utilities for secure random key generation.
- `hash_function`: Hash function traits and implementations (SHA-256, SHA-512, SHAKE128).
- `mobile`: Mobile-specific optimizations (ARM NEON, memory, power management).
- `hardware`: Hardware acceleration interfaces (OpenCL).
- `errors`: Custom error types for CryptKeyper operations.

### 2.3 Usage Examples

#### 2.3.1 Generating an XMSS Key Pair and Signing
```rust
use cryptkeyper::xmss::{Xmss, XmssSignature, XmssPublicKey};
use cryptkeyper::parameters::XmssParameterSet;
use cryptkeyper::errors::Result;

fn main() -> Result<()> {
    // Choose a parameter set (e.g., XMSS-SHA2_256-W16-H10)
    let xmss_params = XmssParameterSet::XmssSha256W16H10;

    // Generate an XMSS instance (this generates the key pair)
    let mut xmss = Xmss::new(xmss_params)?;

    // Message to be signed
    let message = b"This is a test message for XMSS.";

    // Sign the message
    let signature = xmss.sign(message)?;

    // Verify the signature
    let is_valid = Xmss::verify(message, &signature, &xmss.public_key)?;
    assert!(is_valid, "Signature verification failed!");

    println!("XMSS Signature is valid: {}", is_valid);
    println!("Remaining signatures: {}", xmss.remaining_signatures());

    Ok(())
}
```

#### 2.3.2 Using XMSS^MT for Multiple Signatures
```rust
use cryptkeyper::xmss::xmss_mt::{XmssMt, XmssMtSignature, XmssMtPublicKey};
use cryptkeyper::parameters::XmssMtParameterSet;
use cryptkeyper::errors::Result;

fn main() -> Result<()> {
    // Choose an XMSS^MT parameter set
    let xmss_mt_params = XmssMtParameterSet::XmssMtSha256W16H20D2;

    // Create an XMSS^MT instance
    let xmss_mt = XmssMt::new(xmss_mt_params)?;

    let message1 = b"First message for XMSS-MT.";
    let signature1 = xmss_mt.sign(message1)?;
    assert!(XmssMt::verify(message1, &signature1, &xmss_mt.public_key)?);

    let message2 = b"Second message for XMSS-MT.";
    let signature2 = xmss_mt.sign(message2)?;
    assert!(XmssMt::verify(message2, &signature2, &xmss_mt.public_key)?);

    println!("XMSS^MT signatures are valid.");
    println!("Used signatures: {}", xmss_mt.current_index());
    println!("Remaining signatures: {}", xmss_mt.remaining_signatures());

    Ok(())
}
```

### 2.4 Error Handling
CryptKeyper uses a custom `CryptKeyperError` enum for detailed error reporting. Functions typically return `Result<T>`, which is an alias for `std::result::Result<T, CryptKeyperError>`.

Common error types include:
- `InvalidParameter`: Invalid input to a function.
- `KeyGenerationError`: Failure during key pair generation.
- `SignatureError`: Issues during signature creation or verification.
- `NoMoreSignatures`: Attempted to sign after exhausting all available signatures.
- `HardwareError`: Problems with hardware acceleration (e.g., OpenCL initialization).

## 3. Python Bindings

CryptKeyper provides Python bindings for easy integration into Python applications. These bindings leverage the underlying Rust implementation for performance.

### 3.1 Installation
Install via pip (once published):
```bash
pip install cryptkeyper
```
For local development, navigate to `python-bindings` and install:
```bash
pip install -e .
```

### 3.2 Usage Examples

#### 3.2.1 Basic XMSS Usage
```python
from cryptkeyper import Xmss, XmssParameterSet

# Choose a parameter set
xmss_params = XmssParameterSet.XmssSha256W16H10

# Generate an XMSS instance
xmss = Xmss(xmss_params)

# Message to be signed (must be bytes)
message = b"Hello from Python!"

# Sign the message
signature = xmss.sign(message)

# Verify the signature
is_valid = xmss.verify(message, signature)
print(f"Signature valid: {is_valid}")

print(f"Remaining signatures: {xmss.remaining_signatures()}")
```

#### 3.2.2 XMSS^MT Usage
```python
from cryptkeyper import XmssMt, XmssMtParameterSet

# Choose an XMSS^MT parameter set
xmss_mt_params = XmssMtParameterSet.XmssMtSha256W16H20D2

# Create an XMSS^MT instance
xmss_mt = XmssMt(xmss_mt_params)

message1 = b"Python message one."
signature1 = xmss_mt.sign(message1)
print(f"Message 1 valid: {xmss_mt.verify(message1, signature1)}")

message2 = b"Python message two."
signature2 = xmss_mt.sign(message2)
print(f"Message 2 valid: {xmss_mt.verify(message2, signature2)}")

print(f"Used signatures: {xmss_mt.current_index()}")
```

## 4. WASM Bindings

CryptKeyper can be compiled to WebAssembly (WASM), enabling its use in web browsers and Node.js environments. This allows for client-side cryptographic operations with high performance.

### 4.1 Installation
(Details for WASM installation and usage will be provided once the WASM bindings are fully developed and published, likely involving `wasm-pack` and npm.)

### 4.2 Usage Examples
(WASM usage examples will be added here, demonstrating how to import and use the WASM module in JavaScript/TypeScript.)

## 5. Performance Considerations

CryptKeyper is optimized for performance, especially with its hardware acceleration features.
- **Parameter Set Selection:** Choose XMSS/XMSS^MT parameter sets carefully. Larger tree heights and more layers provide more signatures but increase key generation time, signature size, and signing/verification time.
- **Hardware Acceleration:** On supported platforms, enable `opencl` or `arm_neon` features for significant speedups.
- **State Management:** For stateful schemes like XMSS, efficient state management (e.g., storing the current signature index securely) is critical for both security and performance.
- **Caching:** The optimized XMSS implementation (`XmssOptimized`) utilizes caching for tree nodes and authentication paths to reduce recomputation overhead.

## 6. CryptKeyper API Service

This section describes the CryptKeyper API service, built using Rust and `actix-web`, which provides a decoupled interface for certain cryptographic operations.

### 6.1 Endpoints

- **`/hello` (GET):** A simple endpoint to confirm the API service is running.
- **`/xmss/keygen` (POST):** Generates a new XMSS key pair. Returns the public key and the initial private key state. **Important:** The private key state is returned for offline or secure environment management. It is crucial to handle this state with extreme care, as its compromise allows for unauthorized signing.
- **`/xmss/verify` (POST):** Verifies an XMSS signature against a message and a public key. This is a stateless operation.

### 6.2 Important Considerations for Stateful Operations (XMSS Signing)

XMSS is a **stateful** signature scheme. This means that the private key's internal state (specifically, the signature index) changes with each signing operation. Reusing an already used signature index will compromise the security of the entire key pair.

**The CryptKeyper API Service intentionally does NOT provide an endpoint for XMSS signing.** This decision is made to prevent users from inadvertently introducing severe security vulnerabilities by attempting to manage the stateful private key in an insecure manner within a typical stateless API interaction. 

**XMSS signing should be performed in a highly secure, controlled, and typically offline environment.** The `private_key_state` returned by the `/xmss/keygen` endpoint is intended to be used in such an environment. Developers must implement robust, secure storage and management practices for this state to ensure the integrity and security of their cryptographic operations.

### 6.3 Running the API Service

To run the API service, navigate to the project root directory and execute:

```bash
cargo run --package cryptkeyper-api
```

The API will typically be available at `http://127.0.0.1:8080`.

### 6.4 Example API Interactions

**1. Get Hello Message (GET /hello)**

```bash
curl http://127.0.0.1:8080/hello
```

**2. Generate XMSS Key Pair (POST /xmss/keygen)**

```bash
curl -X POST -H "Content-Type: application/json" -d '{"parameter_set": "XmssSha256W16H10"}' http://127.0.0.1:8080/xmss/keygen
```

**3. Verify Signature (POST /xmss/verify)**

```bash
curl -X POST -H "Content-Type: application/json" -d '{
  "message": "My secret message.",
  "signature": {
    "index": 0,
    "wots_signature": [[...], ...],
    "auth_path": [[...], ...]
  },
  "public_key": {
    "root": [...],
    "pub_seed": [...],
    "parameter_set": "XmssSha256W16H10"
  }
}' http://127.0.0.1:8080/xmss/verify
```
