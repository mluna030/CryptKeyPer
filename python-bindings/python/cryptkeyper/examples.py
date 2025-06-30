"""
Example usage of CryptKeyPer for various post-quantum cryptography scenarios
"""

import os
import time
import json
from typing import Dict, List, Tuple, Optional
import cryptkeyper


def basic_signing_example():
    """Basic XMSS signing and verification example."""
    print("🔐 Basic XMSS Signing Example")
    print("=" * 50)
    
    # Create a key pair
    keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
    print(f"✅ Generated key pair: {keypair.parameter_info}")
    print(f"📊 Max signatures: {keypair.max_signatures:,}")
    print(f"⏳ Remaining: {keypair.remaining_signatures:,}")
    
    # Sign a message
    message = b"Hello, post-quantum world! This message is quantum-safe."
    signature = keypair.sign(message)
    print(f"✍️  Signed message ({len(message)} bytes)")
    print(f"📝 Signature size: {len(signature.bytes):,} bytes")
    
    # Verify the signature
    public_key = keypair.public_key
    is_valid = public_key.verify(message, signature)
    print(f"🔍 Signature valid: {is_valid}")
    print(f"⏳ Signatures remaining: {keypair.remaining_signatures:,}")
    
    # Test with wrong message
    wrong_message = b"This is a different message"
    is_invalid = public_key.verify(wrong_message, signature)
    print(f"🚫 Wrong message verification: {is_invalid}")
    print()


def parameter_comparison_example():
    """Compare different XMSS parameter sets."""
    print("📋 Parameter Set Comparison")
    print("=" * 50)
    
    params = cryptkeyper.available_parameter_sets()
    sizes = cryptkeyper.estimate_sizes()
    
    print(f"{'Parameter Set':<25} {'Max Signatures':<15} {'Sig Size':<10} {'Use Case'}")
    print("-" * 70)
    
    for param_name, info in params.items():
        sig_size = sizes.get(param_name, "Unknown")
        if isinstance(sig_size, int):
            sig_size_str = f"{sig_size:,}B"
        else:
            sig_size_str = str(sig_size)
            
        print(f"{param_name:<25} {info['signatures']:<15} {sig_size_str:<10} {info['description']}")
    print()


def performance_benchmark_example():
    """Benchmark different parameter sets."""
    print("⚡ Performance Benchmark")
    print("=" * 50)
    
    test_params = [
        "XMSS-SHA256-W16-H10",
        "XMSS-SHA256-W16-H16", 
        "XMSS-SHA512-W16-H10"
    ]
    
    message = b"Benchmark message for performance testing"
    
    for param in test_params:
        print(f"\n🧪 Testing {param}:")
        
        # Time key generation
        start = time.time()
        keypair = cryptkeyper.generate_keypair(param)
        keygen_time = (time.time() - start) * 1000
        
        # Time signing
        start = time.time()
        signature = keypair.sign(message)
        sign_time = (time.time() - start) * 1000
        
        # Time verification
        start = time.time()
        is_valid = keypair.public_key.verify(message, signature)
        verify_time = (time.time() - start) * 1000
        
        print(f"  🔑 Key generation: {keygen_time:.1f}ms")
        print(f"  ✍️  Signing: {sign_time:.1f}ms") 
        print(f"  🔍 Verification: {verify_time:.1f}ms")
        print(f"  📝 Signature size: {len(signature.bytes):,} bytes")
        print(f"  ✅ Valid: {is_valid}")
    print()


def batch_signing_example():
    """Demonstrate signing multiple messages efficiently."""
    print("📦 Batch Signing Example")
    print("=" * 50)
    
    keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")
    
    # Create test messages
    messages = [
        b"Message 1: Hello World",
        b"Message 2: Post-quantum cryptography is the future",
        b"Message 3: XMSS provides forward security",
        b"Message 4: RFC 8391 compliance ensures interoperability",
        b"Message 5: Python bindings make PQC accessible"
    ]
    
    print(f"📨 Signing {len(messages)} messages...")
    
    signatures = []
    total_start = time.time()
    
    for i, message in enumerate(messages, 1):
        start = time.time()
        signature = keypair.sign(message)
        sign_time = (time.time() - start) * 1000
        
        signatures.append((message, signature))
        print(f"  ✍️  Message {i}: {sign_time:.1f}ms ({len(signature.bytes):,} bytes)")
    
    total_time = (time.time() - total_start) * 1000
    print(f"📊 Total signing time: {total_time:.1f}ms")
    print(f"⏳ Signatures remaining: {keypair.remaining_signatures:,}")
    
    # Verify all signatures
    print(f"\n🔍 Verifying {len(signatures)} signatures...")
    public_key = keypair.public_key
    
    verify_start = time.time()
    all_valid = True
    
    for i, (message, signature) in enumerate(signatures, 1):
        is_valid = public_key.verify(message, signature)
        if not is_valid:
            all_valid = False
        print(f"  ✅ Message {i}: {'Valid' if is_valid else 'INVALID'}")
    
    verify_total = (time.time() - verify_start) * 1000
    print(f"📊 Total verification time: {verify_total:.1f}ms")
    print(f"🎯 All signatures valid: {all_valid}")
    print()


def file_signing_example():
    """Example of signing files or large data."""
    print("📄 File Signing Example")
    print("=" * 50)
    
    # Create a test file
    test_data = b"This is test file content that we want to sign.\n" * 100
    filename = "test_document.txt"
    
    with open(filename, "wb") as f:
        f.write(test_data)
    
    print(f"📁 Created test file: {filename} ({len(test_data):,} bytes)")
    
    # Generate keypair
    keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")
    
    # Sign the file contents
    with open(filename, "rb") as f:
        file_data = f.read()
    
    print("✍️  Signing file...")
    signature = keypair.sign(file_data)
    
    # Save signature
    sig_filename = filename + ".sig"
    with open(sig_filename, "wb") as f:
        f.write(signature.bytes)
    
    print(f"💾 Signature saved to: {sig_filename} ({len(signature.bytes):,} bytes)")
    
    # Save public key
    pubkey_filename = filename + ".pub"
    with open(pubkey_filename, "wb") as f:
        f.write(keypair.public_key.bytes)
    
    print(f"🔑 Public key saved to: {pubkey_filename} ({len(keypair.public_key.bytes)} bytes)")
    
    # Verify the signature
    print("\n🔍 Verifying file signature...")
    
    with open(filename, "rb") as f:
        verify_data = f.read()
    
    with open(sig_filename, "rb") as f:
        verify_signature = cryptkeyper.XmssSignature.from_bytes(f.read())
    
    with open(pubkey_filename, "rb") as f:
        verify_pubkey = cryptkeyper.XmssPublicKey.from_bytes(f.read())
    
    is_valid = verify_pubkey.verify(verify_data, verify_signature)
    print(f"✅ File signature valid: {is_valid}")
    
    # Clean up
    os.remove(filename)
    os.remove(sig_filename)
    os.remove(pubkey_filename)
    print("🧹 Cleaned up test files")
    print()


def deterministic_keys_example():
    """Demonstrate deterministic key generation from seed."""
    print("🎲 Deterministic Key Generation")
    print("=" * 50)
    
    # Use a fixed seed for reproducible keys
    seed = b"This is a 32-byte seed for demo!" # Exactly 32 bytes
    assert len(seed) == 32, "Seed must be exactly 32 bytes"
    
    print(f"🌱 Using seed: {seed.hex()}")
    
    # Generate the same key pair multiple times
    keypair1 = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10", seed)
    keypair2 = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10", seed)
    
    # Public keys should be identical
    pubkey1_bytes = keypair1.public_key.bytes
    pubkey2_bytes = keypair2.public_key.bytes
    
    print(f"🔑 Public key 1: {pubkey1_bytes[:16].hex()}...")
    print(f"🔑 Public key 2: {pubkey2_bytes[:16].hex()}...")
    print(f"✅ Keys identical: {pubkey1_bytes == pubkey2_bytes}")
    
    # Signatures should be different (due to state)
    message = b"Test message for deterministic signing"
    sig1 = keypair1.sign(message)
    sig2 = keypair2.sign(message)  # This will be different!
    
    print(f"📝 Signature 1: {sig1.bytes[:16].hex()}...")
    print(f"📝 Signature 2: {sig2.bytes[:16].hex()}...")
    print(f"🔄 Signatures different: {sig1.bytes != sig2.bytes}")
    print("   (This is expected - XMSS is stateful)")
    
    # Both signatures should verify
    is_valid1 = keypair1.public_key.verify(message, sig1)
    is_valid2 = keypair2.public_key.verify(message, sig2)
    
    print(f"✅ Signature 1 valid: {is_valid1}")
    print(f"✅ Signature 2 valid: {is_valid2}")
    print()


def quick_api_example():
    """Demonstrate the quick/convenience APIs."""
    print("🚀 Quick API Example")
    print("=" * 50)
    
    message = b"Quick and easy post-quantum signing!"
    
    # Quick sign - one function call
    print("✍️  Using quick_sign()...")
    sig_bytes, pubkey_bytes, remaining = cryptkeyper.quick_sign(
        message, 
        "XMSS-SHA256-W16-H10"
    )
    
    print(f"📝 Generated signature ({len(sig_bytes):,} bytes)")
    print(f"🔑 Generated public key ({len(pubkey_bytes)} bytes)")
    print(f"⏳ Signatures remaining: {remaining:,}")
    
    # Quick verify - one function call
    print("\n🔍 Using quick_verify()...")
    is_valid = cryptkeyper.quick_verify(message, sig_bytes, pubkey_bytes)
    print(f"✅ Signature valid: {is_valid}")
    
    # Test with wrong message
    wrong_message = b"This is not the original message"
    is_invalid = cryptkeyper.quick_verify(wrong_message, sig_bytes, pubkey_bytes)
    print(f"🚫 Wrong message: {is_invalid}")
    print()


def main():
    """Run all examples."""
    print("🔮 CryptKeyPer Python Examples")
    print("🛡️  Post-Quantum Cryptography Demo")
    print("📖 RFC 8391 XMSS Implementation")
    print()
    
    examples = [
        basic_signing_example,
        parameter_comparison_example,
        performance_benchmark_example,
        batch_signing_example,
        file_signing_example,
        deterministic_keys_example,
        quick_api_example,
    ]
    
    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"❌ Example failed: {e}")
            print()
    
    print("🎉 All examples completed!")
    print("🔗 Learn more: https://github.com/mluna030/CryptKeyPer")


if __name__ == "__main__":
    main()