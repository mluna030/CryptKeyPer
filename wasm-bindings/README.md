# CryptKeyPer WASM Bindings

WebAssembly bindings for CryptKeyPer - A high-performance, RFC 8391 compliant XMSS (eXtended Merkle Signature Scheme) post-quantum cryptography implementation.

## 🚀 Quick Start

### Browser (ES6 Modules)

```html
<!DOCTYPE html>
<html>
<head>
    <title>Post-Quantum Signatures Demo</title>
</head>
<body>
    <script type="module">
        import init, { WasmXmssKeyPair, init_cryptkeyper } from './pkg/cryptkeyper_wasm.js';
        
        async function demo() {
            await init();
            init_cryptkeyper();
            
            // Generate quantum-safe key pair
            const seed = crypto.getRandomValues(new Uint8Array(32));
            const keyPair = new WasmXmssKeyPair(1, seed); // Medium security
            
            // Sign a message
            const message = new TextEncoder().encode("Hello, quantum-safe world!");
            const signature = keyPair.sign(message);
            
            // Verify signature
            const isValid = keyPair.public_key.verify(message, signature);
            console.log("Signature valid:", isValid);
            console.log("Remaining signatures:", keyPair.remaining_signatures);
        }
        
        demo().catch(console.error);
    </script>
</body>
</html>
```

### Node.js

```javascript
const { WasmXmssKeyPair, init_cryptkeyper } = require('./pkg/cryptkeyper_wasm.js');

// Initialize
init_cryptkeyper();

// Generate key pair
const seed = require('crypto').randomBytes(32);
const keyPair = new WasmXmssKeyPair(1, seed);

// Sign and verify
const message = Buffer.from("Post-quantum signatures in Node.js!");
const signature = keyPair.sign(message);
const isValid = keyPair.public_key.verify(message, signature);

console.log("Signature valid:", isValid);
```

### TypeScript

```typescript
import { WasmXmssKeyPair, WasmUtils, init_cryptkeyper } from 'cryptkeyper-wasm';

async function quantumSafeApp() {
    init_cryptkeyper();
    
    // Check available parameter sets
    const paramSets = WasmUtils.get_parameter_sets();
    console.log("Available parameter sets:", paramSets);
    
    // Create key pair with strong security
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const keyPair = new WasmXmssKeyPair(2, seed); // High security (1M signatures)
    
    // Your quantum-safe application logic here...
}
```

## 📋 Parameter Sets

Choose the right parameter set for your use case:

| ID | Name | Hash | Signatures | Security | Use Case |
|----|------|------|------------|----------|----------|
| 0 | XMSS-SHA256-W16-H10 | SHA-256 | 1,024 | 128-bit | IoT/Short-term |
| 1 | XMSS-SHA256-W16-H16 | SHA-256 | 65,536 | 128-bit | General purpose |
| 2 | XMSS-SHA256-W16-H20 | SHA-256 | 1,048,576 | 128-bit | Long-term/CA |
| 3 | XMSS-SHA512-W16-H10 | SHA-512 | 1,024 | 256-bit | High security/IoT |
| 4 | XMSS-SHA512-W16-H16 | SHA-512 | 65,536 | 256-bit | High security |
| 5 | XMSS-SHA512-W16-H20 | SHA-512 | 1,048,576 | 256-bit | Maximum security |
| 6 | XMSS-SHAKE128-W16-H10 | SHAKE128 | 1,024 | 128-bit | Research/Alternative |
| 7 | XMSS-SHAKE128-W16-H16 | SHAKE128 | 65,536 | 128-bit | Research/Alternative |
| 8 | XMSS-SHAKE128-W16-H20 | SHAKE128 | 1,048,576 | 128-bit | Research/Alternative |

## 🛡️ Security Features

- **Quantum-Resistant**: Secure against both classical and quantum computers
- **RFC 8391 Compliant**: Follows official XMSS specification
- **Forward Secure**: Past signatures remain secure even if private key is compromised
- **One-Time Use**: Each signature uses a unique one-time key
- **Hash-Based**: Security based on collision-resistant hash functions

## 🔧 API Reference

### `WasmXmssKeyPair`

```typescript
class WasmXmssKeyPair {
    constructor(parameter_set: number, seed: Uint8Array);
    
    // Properties
    readonly public_key: WasmXmssPublicKey;
    readonly remaining_signatures: number;
    readonly max_signatures: number;
    readonly parameter_info: string;
    
    // Methods
    sign(message: Uint8Array): WasmXmssSignature;
    export_private_key(): Uint8Array; // ⚠️ Use with extreme caution
}
```

### `WasmXmssPublicKey`

```typescript
class WasmXmssPublicKey {
    constructor(bytes: Uint8Array);
    
    readonly bytes: Uint8Array;
    readonly size: number;
    
    verify(message: Uint8Array, signature: WasmXmssSignature): boolean;
}
```

### `WasmXmssSignature`

```typescript
class WasmXmssSignature {
    constructor(bytes: Uint8Array);
    
    readonly bytes: Uint8Array;
    readonly size: number;
}
```

### `WasmUtils`

```typescript
class WasmUtils {
    static get_parameter_sets(): ParameterSetInfo[];
    static version_info(): string;
    static benchmark_parameter_set(id: number): Promise<BenchmarkResult>;
}
```

## ⚡ Performance

Approximate performance on modern hardware:

| Operation | Time | Notes |
|-----------|------|-------|
| Key Generation | 1-100ms | Depends on parameter set |
| Signing | 0.5-50ms | Depends on tree height |
| Verification | 0.1-10ms | Generally fast |
| Signature Size | 2.5-9KB | Larger than classical schemes |

## 🔐 Security Considerations

### ⚠️ Important Warnings

1. **State Management**: XMSS is stateful - never reuse signature indices
2. **Key Storage**: Store private keys securely and back up state
3. **Signature Limit**: Plan for the maximum number of signatures needed
4. **Seed Quality**: Use cryptographically secure random seeds

### Best Practices

```typescript
// ✅ Good: Secure seed generation
const seed = crypto.getRandomValues(new Uint8Array(32));

// ❌ Bad: Predictable seed
const badSeed = new Uint8Array(32).fill(42);

// ✅ Good: Check remaining signatures
if (keyPair.remaining_signatures > 100) {
    const signature = keyPair.sign(message);
} else {
    console.warn("Running low on signatures!");
}

// ✅ Good: Verify signatures
const isValid = publicKey.verify(message, signature);
if (!isValid) {
    throw new Error("Invalid signature detected!");
}
```

## 🧪 Examples

### Password-Based Key Derivation

```typescript
import { CryptKeyperIntegration } from './example.js';

async function createAccountSignature(password: string, userData: string) {
    // Derive key pair from password
    const { keyPair, salt } = await CryptKeyperIntegration
        .createKeyPairFromPassword(password, 1);
    
    // Sign user data
    const data = new TextEncoder().encode(userData);
    const signature = keyPair.sign(data);
    
    return {
        publicKey: keyPair.public_key.bytes,
        signature: signature.bytes,
        salt: salt
    };
}
```

### File Signing

```typescript
async function signFile(keyPair: WasmXmssKeyPair, file: File): Promise<Uint8Array> {
    const fileData = await file.arrayBuffer();
    return CryptKeyperIntegration.signFile(keyPair, new Uint8Array(fileData));
}
```

### Batch Verification

```typescript
function verifyMultipleSignatures(
    publicKey: WasmXmssPublicKey, 
    items: Array<{message: Uint8Array, signature: WasmXmssSignature}>
): boolean[] {
    return CryptKeyperIntegration.batchVerify(publicKey, items)
        .map(result => result.valid);
}
```

## 🏗️ Building from Source

```bash
# Install dependencies
cargo install wasm-pack

# Build for web
wasm-pack build --target web --scope cryptkeyper

# Build for Node.js
wasm-pack build --target nodejs --scope cryptkeyper

# Build for bundlers (webpack, etc.)
wasm-pack build --target bundler --scope cryptkeyper
```

## 🔬 Testing

```bash
# Run the demo
node example.js

# Serve browser demo
npm run serve
# Then open http://localhost:8000
```

## 📚 Learn More

- [RFC 8391 - XMSS Specification](https://tools.ietf.org/rfc/rfc8391.txt)
- [Post-Quantum Cryptography FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs)
- [NIST PQC Competition](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [Quantum Computing Threat Timeline](https://globalriskinstitute.org/publications/2700-2/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.

## 🆘 Support

- 📝 [GitHub Issues](https://github.com/mluna030/CryptKeyPer/issues)
- 💬 [Discussions](https://github.com/mluna030/CryptKeyPer/discussions)
- 📧 [Email Support](mailto:michael.angelo.luna1@gmail.com)

---

**⚡ Ready for the quantum future? Start using post-quantum signatures today! ⚡**