"""
Performance tests and benchmarks for CryptKeyPer Python bindings
"""

import time
import pytest
import cryptkeyper


class TestPerformanceBenchmarks:
    """Performance benchmarks for different operations."""
    
    @pytest.mark.benchmark
    def test_key_generation_performance(self):
        """Benchmark key generation for different parameter sets."""
        parameter_sets = [
            "XMSS-SHA256-W16-H10",
            "XMSS-SHA256-W16-H16", 
            "XMSS-SHA512-W16-H10"
        ]
        
        results = {}
        
        for param_set in parameter_sets:
            times = []
            for _ in range(3):  # Multiple runs for average
                start = time.time()
                keypair = cryptkeyper.XmssKeyPair(param_set)
                end = time.time()
                times.append((end - start) * 1000)  # Convert to ms
            
            avg_time = sum(times) / len(times)
            results[param_set] = avg_time
            print(f"Key generation {param_set}: {avg_time:.1f}ms")
            
            # Reasonable performance expectations
            assert avg_time < 1000.0  # Should be under 1 second
            
    @pytest.mark.benchmark
    def test_signing_performance(self):
        """Benchmark signing performance."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")
        message = b"Performance test message for signing benchmarks"
        
        # Warm up
        keypair.sign(message)
        
        # Benchmark multiple signings
        sign_times = []
        for _ in range(10):
            start = time.time()
            signature = keypair.sign(message)
            end = time.time()
            sign_times.append((end - start) * 1000)
            
        avg_sign_time = sum(sign_times) / len(sign_times)
        print(f"Average signing time: {avg_sign_time:.1f}ms")
        print(f"Signature size: {len(signature.bytes):,} bytes")
        
        # Performance expectations
        assert avg_sign_time < 200.0  # Should be under 200ms
        assert len(signature.bytes) < 10000  # Reasonable signature size
        
    @pytest.mark.benchmark
    def test_verification_performance(self):
        """Benchmark verification performance."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")
        message = b"Performance test message for verification benchmarks"
        signature = keypair.sign(message)
        public_key = keypair.public_key
        
        # Benchmark multiple verifications
        verify_times = []
        for _ in range(50):  # More iterations since verification is faster
            start = time.time()
            is_valid = public_key.verify(message, signature)
            end = time.time()
            verify_times.append((end - start) * 1000)
            assert is_valid is True
            
        avg_verify_time = sum(verify_times) / len(verify_times)
        print(f"Average verification time: {avg_verify_time:.1f}ms")
        
        # Performance expectations
        assert avg_verify_time < 50.0  # Should be under 50ms
        
    @pytest.mark.benchmark
    def test_throughput_benchmark(self):
        """Test signing and verification throughput."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")
        messages = [f"Message {i}".encode() for i in range(100)]
        
        # Signing throughput
        start_time = time.time()
        signatures = []
        for message in messages:
            sig = keypair.sign(message)
            signatures.append(sig)
        signing_time = time.time() - start_time
        
        signing_throughput = len(messages) / signing_time
        print(f"Signing throughput: {signing_throughput:.1f} signatures/second")
        
        # Verification throughput  
        public_key = keypair.public_key
        start_time = time.time()
        valid_count = 0
        for message, signature in zip(messages, signatures):
            if public_key.verify(message, signature):
                valid_count += 1
        verification_time = time.time() - start_time
        
        verification_throughput = len(messages) / verification_time
        print(f"Verification throughput: {verification_throughput:.1f} verifications/second")
        
        assert valid_count == len(messages)  # All should be valid
        assert signing_throughput > 1.0  # At least 1 signature per second
        assert verification_throughput > 10.0  # At least 10 verifications per second


class TestScalabilityTests:
    """Test scalability with different data sizes and parameter sets."""
    
    @pytest.mark.slow
    def test_large_message_performance(self):
        """Test performance with large messages."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H10")
        
        message_sizes = [1024, 10240, 102400, 1024000]  # 1KB to 1MB
        
        for size in message_sizes:
            message = b"A" * size
            
            # Time signing
            start = time.time()
            signature = keypair.sign(message)
            sign_time = (time.time() - start) * 1000
            
            # Time verification
            start = time.time()
            is_valid = keypair.public_key.verify(message, signature)
            verify_time = (time.time() - start) * 1000
            
            print(f"Message size: {size:,} bytes")
            print(f"  Sign time: {sign_time:.1f}ms")
            print(f"  Verify time: {verify_time:.1f}ms")
            
            assert is_valid is True
            # Performance should scale reasonably with message size
            assert sign_time < size * 0.01  # Very loose bound
            assert verify_time < size * 0.01
            
    @pytest.mark.benchmark 
    def test_parameter_set_comparison(self):
        """Compare performance across parameter sets."""
        parameter_sets = [
            "XMSS-SHA256-W16-H10",
            "XMSS-SHA256-W16-H16",
            "XMSS-SHA256-W16-H20",
            "XMSS-SHA512-W16-H10"
        ]
        
        message = b"Parameter set comparison test message"
        results = {}
        
        for param_set in parameter_sets:
            # Key generation time
            start = time.time()
            keypair = cryptkeyper.XmssKeyPair(param_set)
            keygen_time = (time.time() - start) * 1000
            
            # Signing time
            start = time.time()
            signature = keypair.sign(message)
            sign_time = (time.time() - start) * 1000
            
            # Verification time
            start = time.time()
            is_valid = keypair.public_key.verify(message, signature)
            verify_time = (time.time() - start) * 1000
            
            results[param_set] = {
                'keygen_ms': keygen_time,
                'sign_ms': sign_time,
                'verify_ms': verify_time,
                'sig_size': len(signature.bytes),
                'max_sigs': keypair.max_signatures
            }
            
            assert is_valid is True
            
        # Print comparison table
        print("\nParameter Set Performance Comparison:")
        print(f"{'Parameter Set':<25} {'KeyGen(ms)':<12} {'Sign(ms)':<10} {'Verify(ms)':<12} {'Sig Size':<10} {'Max Sigs'}")
        print("-" * 90)
        
        for param_set, data in results.items():
            print(f"{param_set:<25} {data['keygen_ms']:<12.1f} {data['sign_ms']:<10.1f} "
                  f"{data['verify_ms']:<12.1f} {data['sig_size']:<10,} {data['max_sigs']:,}")


class TestMemoryUsage:
    """Test memory usage patterns."""
    
    def test_signature_accumulation(self):
        """Test memory usage when accumulating many signatures."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")
        message = b"Memory test message"
        
        # Accumulate signatures
        signatures = []
        for i in range(100):
            sig = keypair.sign(message)
            signatures.append(sig)
            
            # Verify periodically to ensure correctness
            if i % 10 == 0:
                is_valid = keypair.public_key.verify(message, sig)
                assert is_valid is True
                
        print(f"Accumulated {len(signatures)} signatures")
        print(f"Remaining signatures: {keypair.remaining_signatures:,}")
        
        # Test that all signatures are still valid
        public_key = keypair.public_key
        for i, sig in enumerate(signatures):
            is_valid = public_key.verify(message, sig)
            assert is_valid is True, f"Signature {i} became invalid"


class TestStressTests:
    """Stress tests for edge cases and limits."""
    
    @pytest.mark.slow
    def test_signature_exhaustion_approaching_limit(self):
        """Test behavior when approaching signature limit."""
        # Use small parameter set to test exhaustion quickly
        keypair = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10")  # 1024 signatures
        message = b"Exhaustion test"
        
        initial_remaining = keypair.remaining_signatures
        
        # Use up most signatures (but not all, to avoid errors)
        signatures_to_use = min(100, initial_remaining - 10)
        
        for i in range(signatures_to_use):
            signature = keypair.sign(message)
            remaining = keypair.remaining_signatures
            
            assert len(signature.bytes) > 0
            assert remaining == initial_remaining - i - 1
            
            # Verify the signature
            is_valid = keypair.public_key.verify(message, signature)
            assert is_valid is True
            
        print(f"Used {signatures_to_use} signatures")
        print(f"Remaining: {keypair.remaining_signatures}")
        
    def test_concurrent_verification(self):
        """Test multiple concurrent verifications (simulation)."""
        keypair = cryptkeyper.generate_keypair("XMSS-SHA256-W16-H16")
        
        # Create multiple message-signature pairs
        test_cases = []
        for i in range(50):
            message = f"Concurrent test message {i}".encode()
            signature = keypair.sign(message)
            test_cases.append((message, signature))
            
        public_key = keypair.public_key
        
        # Verify all signatures (simulating concurrent access)
        start_time = time.time()
        results = []
        for message, signature in test_cases:
            is_valid = public_key.verify(message, signature)
            results.append(is_valid)
            
        total_time = time.time() - start_time
        
        # All should be valid
        assert all(results)
        print(f"Verified {len(test_cases)} signatures in {total_time:.3f}s")
        print(f"Average verification time: {(total_time/len(test_cases))*1000:.1f}ms")


if __name__ == "__main__":
    # Run only benchmark tests
    pytest.main([__file__, "-m", "benchmark", "-v"])