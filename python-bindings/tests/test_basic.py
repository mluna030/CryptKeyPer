"""
Basic tests for CryptKeyPer Python bindings
"""

import pytest
import cryptkeyper


class TestBasicFunctionality:
    """Test basic XMSS functionality."""
    
    def test_key_generation(self):
        """Test basic key generation."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
        
        assert keypair.max_signatures == 1024
        assert keypair.remaining_signatures == 1024
        assert len(keypair.public_key.bytes) > 0
        
    def test_signing_and_verification(self):
        """Test basic signing and verification."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
        message = b"Test message for signing"
        
        # Sign the message
        signature = keypair.sign(message)
        assert len(signature.bytes) > 0
        assert keypair.remaining_signatures == 1023  # One signature used
        
        # Verify the signature
        is_valid = keypair.public_key.verify(message, signature)
        assert is_valid is True
        
        # Verify with wrong message should fail
        wrong_message = b"Different message"
        is_invalid = keypair.public_key.verify(wrong_message, signature)
        assert is_invalid is False
        
    def test_parameter_sets(self):
        """Test different parameter sets."""
        test_params = [
            ("XMSS-SHA256-W16-H10", 1024),
            ("XMSS-SHA256-W16-H16", 65536),
            ("XMSS-SHA512-W16-H10", 1024),
        ]
        
        for param_name, expected_max in test_params:
            keypair = cryptkeyper.XmssKeyPair(param_name)
            assert keypair.max_signatures == expected_max
            
    def test_deterministic_keys(self):
        """Test deterministic key generation with seeds."""
        seed = b"This is a test seed of 32 bytes!"
        assert len(seed) == 32
        
        # Generate two key pairs with same seed
        keypair1 = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10", seed)
        keypair2 = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10", seed)
        
        # Public keys should be identical
        assert keypair1.public_key.bytes == keypair2.public_key.bytes
        
    def test_signature_serialization(self):
        """Test signature and public key serialization."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
        message = b"Serialization test"
        
        # Create signature
        signature = keypair.sign(message)
        original_sig_bytes = signature.bytes
        
        # Serialize and deserialize signature
        restored_signature = cryptkeyper.XmssSignature.from_bytes(original_sig_bytes)
        assert restored_signature.bytes == original_sig_bytes
        
        # Serialize and deserialize public key
        original_pubkey_bytes = keypair.public_key.bytes
        restored_pubkey = cryptkeyper.XmssPublicKey.from_bytes(original_pubkey_bytes)
        assert restored_pubkey.bytes == original_pubkey_bytes
        
        # Verify with restored objects
        is_valid = restored_pubkey.verify(message, restored_signature)
        assert is_valid is True


class TestQuickAPI:
    """Test convenience/quick API functions."""
    
    def test_quick_sign_verify(self):
        """Test quick_sign and quick_verify functions."""
        message = b"Quick API test message"
        
        # Quick sign
        sig_bytes, pubkey_bytes, remaining = cryptkeyper.quick_sign(
            message, "XMSS-SHA256-W16-H10"
        )
        
        assert len(sig_bytes) > 0
        assert len(pubkey_bytes) > 0
        assert remaining == 1023  # One signature used
        
        # Quick verify
        is_valid = cryptkeyper.quick_verify(message, sig_bytes, pubkey_bytes)
        assert is_valid is True
        
        # Verify with wrong message
        wrong_message = b"Wrong message"
        is_invalid = cryptkeyper.quick_verify(wrong_message, sig_bytes, pubkey_bytes)
        assert is_invalid is False


class TestUtilities:
    """Test utility functions."""
    
    def test_parameter_sets_info(self):
        """Test parameter sets information retrieval."""
        params = cryptkeyper.available_parameter_sets()
        
        assert isinstance(params, dict)
        assert len(params) > 0
        
        # Check specific parameter set
        assert "XMSS-SHA256-W16-H10" in params
        info = params["XMSS-SHA256-W16-H10"]
        assert "signatures" in info
        assert "description" in info
        assert info["quantum_safe"] is True
        
    def test_signature_size_estimates(self):
        """Test signature size estimation."""
        sizes = cryptkeyper.estimate_sizes()
        
        assert isinstance(sizes, dict)
        assert len(sizes) > 0
        
        # Check that sizes are reasonable
        for param_name, size in sizes.items():
            assert isinstance(size, int)
            assert 1000 < size < 10000  # Reasonable signature size range
            
    def test_random_seed_generation(self):
        """Test random seed generation."""
        seed1 = cryptkeyper.CryptKeyperUtils.generate_random_seed()
        seed2 = cryptkeyper.CryptKeyperUtils.generate_random_seed()
        
        assert len(seed1) == 32
        assert len(seed2) == 32
        assert seed1 != seed2  # Should be different random seeds


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_invalid_parameter_set(self):
        """Test handling of invalid parameter sets."""
        with pytest.raises(ValueError):
            cryptkeyper.XmssKeyPair("INVALID-PARAMETER-SET")
            
    def test_invalid_seed_length(self):
        """Test handling of invalid seed lengths."""
        with pytest.raises(ValueError):
            bad_seed = b"Too short"  # Not 32 bytes
            cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10", bad_seed)
            
    def test_signature_exhaustion(self):
        """Test behavior when running out of signatures."""
        # Use smallest parameter set for quick testing
        keypair = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10")
        message = b"Test message"
        
        initial_remaining = keypair.remaining_signatures
        
        # Sign a few messages
        for i in range(5):
            signature = keypair.sign(message)
            assert len(signature.bytes) > 0
            assert keypair.remaining_signatures == initial_remaining - i - 1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_message(self):
        """Test signing empty messages."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
        empty_message = b""
        
        signature = keypair.sign(empty_message)
        is_valid = keypair.public_key.verify(empty_message, signature)
        assert is_valid is True
        
    def test_large_message(self):
        """Test signing large messages."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
        large_message = b"A" * 1000000  # 1MB message
        
        signature = keypair.sign(large_message)
        is_valid = keypair.public_key.verify(large_message, signature)
        assert is_valid is True
        
    def test_unicode_handling(self):
        """Test handling of unicode strings."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
        unicode_text = "Hello, 世界! 🌍 Quantum-safe signatures"
        message = unicode_text.encode('utf-8')
        
        signature = keypair.sign(message)
        is_valid = keypair.public_key.verify(message, signature)
        assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__])