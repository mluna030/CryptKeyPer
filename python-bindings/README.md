# CryptKeyPer Python Bindings

Python bindings for CryptKeyPer - A high-performance, RFC 8391 compliant XMSS (eXtended Merkle Signature Scheme) post-quantum cryptography implementation.

## Quick Start

### Installation

```bash
# Install from PyPI (when published)
pip install cryptkeyper

# Or install from source
pip install maturin
maturin develop --release
```

### Basic Usage

```python
import cryptkeyper

# Generate a quantum-safe key pair
keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")

# Sign a message
message = b"Hello, post-quantum world!"
signature = keypair.sign(message)

# Verify the signature
is_valid = keypair.public_key.verify(message, signature)
print(f"Signature valid: {is_valid}")

# Check remaining signatures
print(f"Remaining signatures: {keypair.remaining_signatures:,}")
```

## Parameter Sets

Choose the right parameter set for your security and performance needs:

| Parameter Set | Max Signatures | Security Level | Use Case |
|---------------|----------------|----------------|----------|
| `XMSS-SHA256-W16-H10` | 1,024 | 128-bit | IoT/Embedded |
| `XMSS-SHA256-W16-H16` | 65,536 | 128-bit | General Purpose |
| `XMSS-SHA256-W16-H20` | 1,048,576 | 128-bit | Long-term/CA |
| `XMSS-SHA512-W16-H10` | 1,024 | 256-bit | High Security |
| `XMSS-SHA512-W16-H16` | 65,536 | 256-bit | High Security |
| `XMSS-SHA512-W16-H20` | 1,048,576 | 256-bit | Maximum Security |

```python
# List all available parameter sets
params = cryptkeyper.available_parameter_sets()
for name, info in params.items():
    print(f"{name}: {info['signatures']} - {info['description']}")
```

## API Reference

### `XmssKeyPair`

The main class for XMSS key generation and signing.

```python
class XmssKeyPair:
    def __init__(self, parameter_set: str, seed: bytes = None):
        """Create a new XMSS key pair.
        
        Args:
            parameter_set: Parameter set name (e.g., "XMSS-SHA256-W16-H16")
            seed: Optional 32-byte seed for deterministic generation
        """
    
    def sign(self, message: bytes) -> XmssSignature:
        """Sign a message."""
    
    @property
    def public_key(self) -> XmssPublicKey:
        """Get the public key."""
    
    @property
    def remaining_signatures(self) -> int:
        """Get number of remaining signatures."""
    
    @property
    def max_signatures(self) -> int:
        """Get maximum signatures for this parameter set."""
```

### `XmssPublicKey`

Public key for signature verification.

```python
class XmssPublicKey:
    def verify(self, message: bytes, signature: XmssSignature) -> bool:
        """Verify a signature."""
    
    @property
    def bytes(self) -> bytes:
        """Get public key as bytes."""
    
    @staticmethod
    def from_bytes(data: bytes) -> XmssPublicKey:
        """Create public key from bytes."""
```

### `XmssSignature`

XMSS signature container.

```python
class XmssSignature:
    @property
    def bytes(self) -> bytes:
        """Get signature as bytes."""
    
    @property
    def size(self) -> int:
        """Get signature size in bytes."""
    
    @staticmethod
    def from_bytes(data: bytes) -> XmssSignature:
        """Create signature from bytes."""
```

### Convenience Functions

```python
def quick_sign(message: bytes, parameter_set: str = "XMSS-SHA256-W16-H10", 
               seed: bytes = None) -> tuple[bytes, bytes, int]:
    """Quick sign - create keypair and sign in one call.
    
    Returns:
        (signature_bytes, public_key_bytes, remaining_signatures)
    """

def quick_verify(message: bytes, signature_bytes: bytes, 
                 public_key_bytes: bytes) -> bool:
    """Quick verify - verify signature without creating objects."""
```

## Examples

### Basic Signing

```python
import cryptkeyper

# Create key pair
keypair = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H16")

# Sign a message
message = b"Important document content"
signature = keypair.sign(message)

# Verify signature
is_valid = keypair.public_key.verify(message, signature)
print(f"Valid: {is_valid}")
```

### File Signing

```python
import cryptkeyper

# Generate key pair
keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")

# Sign file
with open("document.pdf", "rb") as f:
    file_data = f.read()

signature = keypair.sign(file_data)

# Save signature and public key
with open("document.pdf.sig", "wb") as f:
    f.write(signature.bytes)

with open("document.pdf.pub", "wb") as f:
    f.write(keypair.public_key.bytes)

# Verify later
with open("document.pdf", "rb") as f:
    verify_data = f.read()

with open("document.pdf.sig", "rb") as f:
    verify_sig = cryptkeyper.XmssSignature.from_bytes(f.read())

with open("document.pdf.pub", "rb") as f:
    verify_pubkey = cryptkeyper.XmssPublicKey.from_bytes(f.read())

is_valid = verify_pubkey.verify(verify_data, verify_sig)
print(f"File signature valid: {is_valid}")
```

### Deterministic Keys

```python
import cryptkeyper

# Use same seed to generate identical key pairs
seed = b"My secure 32-byte seed string!"  # Exactly 32 bytes

keypair1 = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10", seed)
keypair2 = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10", seed)

# Public keys will be identical
assert keypair1.public_key.bytes == keypair2.public_key.bytes
```

### Batch Operations

```python
import cryptkeyper

keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")

# Sign multiple messages
messages = [
    b"Message 1",
    b"Message 2", 
    b"Message 3"
]

signatures = []
for message in messages:
    sig = keypair.sign(message)
    signatures.append((message, sig))

print(f"Signed {len(signatures)} messages")
print(f"Remaining: {keypair.remaining_signatures:,}")

# Verify all signatures
public_key = keypair.public_key
for message, signature in signatures:
    is_valid = public_key.verify(message, signature)
    print(f"Message valid: {is_valid}")
```

### Performance Benchmarking

```python
import time
import cryptkeyper

def benchmark_parameter_set(param_set: str, num_operations: int = 10):
    """Benchmark a parameter set."""
    print(f"Benchmarking {param_set}:")
    
    # Time key generation
    start = time.time()
    keypair = cryptkeyper.generate_keypair(param_set)
    keygen_time = (time.time() - start) * 1000
    
    message = b"Benchmark message"
    
    # Time signing
    sign_times = []
    for _ in range(num_operations):
        start = time.time()
        signature = keypair.sign(message)
        sign_times.append((time.time() - start) * 1000)
    
    # Time verification
    verify_times = []
    for _ in range(num_operations):
        start = time.time()
        is_valid = keypair.public_key.verify(message, signature)
        verify_times.append((time.time() - start) * 1000)
    
    print(f"  Key generation: {keygen_time:.1f}ms")
    print(f"  Signing avg: {sum(sign_times)/len(sign_times):.1f}ms")
    print(f"  Verification avg: {sum(verify_times)/len(verify_times):.1f}ms")
    print(f"  Signature size: {len(signature.bytes):,} bytes")

# Benchmark different parameter sets
for param in ["XMSS-SHA256-W16-H10", "XMSS-SHA256-W16-H16", "XMSS-SHA512-W16-H10"]:
    benchmark_parameter_set(param)
    print()
```

## Performance

Typical performance on modern hardware:

| Operation | Time | Notes |
|-----------|------|-------|
| Key Generation | 10-100ms | Depends on parameter set |
| Signing | 5-50ms | Depends on tree height |
| Verification | 1-10ms | Generally fast |
| Signature Size | 2.5-6KB | Larger than classical schemes |

## Security Considerations

### Important Warnings

1. **Stateful Signatures**: XMSS is stateful - never reuse signature indices
2. **Key Management**: Store private keys securely and maintain state
3. **Signature Limits**: Plan for the maximum number of signatures needed
4. **Seed Quality**: Use cryptographically secure random seeds

### Best Practices

```python
import cryptkeyper

# Good: Use cryptographically secure random seed
seed = cryptkeyper.CryptKeyperUtils.generate_random_seed()
keypair = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H16", seed)

# Good: Check remaining signatures
if keypair.remaining_signatures > 100:
    signature = keypair.sign(message)
else:
    print("Warning: Running low on signatures!")

# Good: Always verify signatures
is_valid = public_key.verify(message, signature)
if not is_valid:
    raise ValueError("Invalid signature detected!")

# Bad: Don't use predictable seeds
# bad_seed = b"0" * 32  # Predictable!

# Bad: Don't ignore remaining signature count
# Could run out of signatures unexpectedly
```

## Testing

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run benchmarks
pytest tests/ -m benchmark

# Run with coverage
pytest --cov=cryptkeyper tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.

## Links

- [RFC 8391 - XMSS Specification](https://tools.ietf.org/rfc/rfc8391.txt)
- [GitHub Repository](https://github.com/mluna030/CryptKeyPer)
- [Documentation](https://cryptkeyper.readthedocs.io)
- [NIST PQC Competition](https://csrc.nist.gov/Projects/post-quantum-cryptography)

---

**Ready for the quantum future? Start using post-quantum signatures today!**
