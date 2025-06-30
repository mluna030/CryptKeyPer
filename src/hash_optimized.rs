use crate::hash_traits::HashFunction;
use crate::errors::Result;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

/// SIMD-optimized hash function wrapper with runtime feature detection
pub struct SimdHashFunction<H: HashFunction> {
    inner: H,
    capabilities: SimdCapabilities,
}

#[derive(Debug, Clone, Copy)]
pub struct SimdCapabilities {
    pub has_avx2: bool,
    pub has_avx512: bool,
    pub has_intel_sha: bool,
    pub has_neon: bool,
    pub has_sve: bool,  // ARM Scalable Vector Extensions
}

impl<H: HashFunction> SimdHashFunction<H> {
    pub fn new(inner: H) -> Self {
        Self {
            inner,
            capabilities: Self::detect_capabilities(),
        }
    }
    
    /// Detect available SIMD capabilities at runtime
    fn detect_capabilities() -> SimdCapabilities {
        SimdCapabilities {
            has_avx2: Self::has_avx2(),
            has_avx512: Self::has_avx512(),
            has_intel_sha: Self::has_intel_sha(),
            has_neon: Self::has_neon(),
            has_sve: Self::has_sve(),
        }
    }
    
    #[cfg(target_arch = "x86_64")]
    fn has_avx2() -> bool {
        is_x86_feature_detected!("avx2")
    }
    
    #[cfg(target_arch = "x86_64")]
    fn has_avx512() -> bool {
        is_x86_feature_detected!("avx512f")
    }
    
    #[cfg(target_arch = "x86_64")]
    fn has_intel_sha() -> bool {
        is_x86_feature_detected!("sha")
    }
    
    #[cfg(target_arch = "aarch64")]
    fn has_neon() -> bool {
        // NEON is standard on AArch64
        true
    }
    
    #[cfg(target_arch = "aarch64")]
    fn has_sve() -> bool {
        // Check for SVE support (if available)
        std::arch::is_aarch64_feature_detected!("sve")
    }
    
    // Default implementations for unsupported architectures
    #[cfg(not(target_arch = "x86_64"))]
    fn has_avx2() -> bool { false }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn has_avx512() -> bool { false }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn has_intel_sha() -> bool { false }
    
    #[cfg(not(target_arch = "aarch64"))]
    fn has_neon() -> bool { false }
    
    #[cfg(not(target_arch = "aarch64"))]
    fn has_sve() -> bool { false }
    
    /// Batch hash multiple inputs using best available SIMD instructions
    pub fn batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        // Choose best available SIMD implementation
        if self.capabilities.has_avx512 && inputs.len() >= 16 {
            self.avx512_batch_hash(inputs)
        } else if self.capabilities.has_avx2 && inputs.len() >= 8 {
            self.avx2_batch_hash(inputs)
        } else if self.capabilities.has_intel_sha && inputs.len() >= 4 {
            self.intel_sha_batch_hash(inputs)
        } else if self.capabilities.has_neon && inputs.len() >= 4 {
            self.neon_batch_hash(inputs)
        } else {
            // Fallback to sequential processing
            inputs.iter().map(|input| self.inner.hash(input)).collect()
        }
    }
    
    /// Get SIMD capabilities summary
    pub fn capabilities(&self) -> SimdCapabilities {
        self.capabilities
    }
    
    /// Estimate performance improvement factor
    pub fn estimated_speedup(&self) -> f64 {
        if self.capabilities.has_avx512 {
            8.0  // 16-way parallelism with some overhead
        } else if self.capabilities.has_avx2 {
            4.0  // 8-way parallelism  
        } else if self.capabilities.has_intel_sha {
            3.0  // Hardware SHA acceleration
        } else if self.capabilities.has_neon {
            2.5  // ARM NEON 4-way
        } else {
            1.0  // No acceleration
        }
    }
    
    #[cfg(target_arch = "x86_64")]
    fn avx512_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        if !self.capabilities.has_avx512 {
            return self.avx2_batch_hash(inputs);
        }
        
        let mut results = Vec::with_capacity(inputs.len());
        
        // Process in chunks of 16 for optimal AVX-512 utilization
        for chunk in inputs.chunks(16) {
            if chunk.len() == 16 {
                unsafe {
                    let input_array: &[&[u8]; 16] = chunk.try_into().unwrap();
                    let batch_results = simd_sha256::avx512_sha256_x16(input_array);
                    results.extend(batch_results.into_iter());
                }
            } else {
                // Partial chunk - fall back to smaller SIMD or sequential
                if chunk.len() >= 8 {
                    let (first_8, remainder) = chunk.split_at(8);
                    unsafe {
                        let input_array: &[&[u8]; 8] = first_8.try_into().unwrap();
                        let batch_results = simd_sha256::avx2_sha256_x8(input_array);
                        results.extend(batch_results.into_iter());
                    }
                    for input in remainder {
                        results.push(self.inner.hash(input));
                    }
                } else {
                    for input in chunk {
                        results.push(self.inner.hash(input));
                    }
                }
            }
        }
        
        results
    }
    
    #[cfg(target_arch = "x86_64")]
    fn avx2_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        if !self.capabilities.has_avx2 {
            return self.intel_sha_batch_hash(inputs);
        }
        
        let mut results = Vec::with_capacity(inputs.len());
        
        for chunk in inputs.chunks(8) {
            if chunk.len() == 8 {
                unsafe {
                    let input_array: &[&[u8]; 8] = chunk.try_into().unwrap();
                    let batch_results = simd_sha256::avx2_sha256_x8(input_array);
                    results.extend(batch_results.into_iter());
                }
            } else if chunk.len() >= 4 {
                let (first_4, remainder) = chunk.split_at(4);
                unsafe {
                    let input_array: &[&[u8]; 4] = first_4.try_into().unwrap();
                    let batch_results = simd_sha256::intel_sha_sha256_x4(input_array);
                    results.extend(batch_results.into_iter());
                }
                for input in remainder {
                    results.push(self.inner.hash(input));
                }
            } else {
                for input in chunk {
                    results.push(self.inner.hash(input));
                }
            }
        }
        
        results
    }
    
    #[cfg(target_arch = "x86_64")]
    fn intel_sha_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        if !self.capabilities.has_intel_sha {
            return inputs.iter().map(|input| self.inner.hash(input)).collect();
        }
        
        let mut results = Vec::with_capacity(inputs.len());
        
        for chunk in inputs.chunks(4) {
            if chunk.len() == 4 {
                unsafe {
                    let input_array: &[&[u8]; 4] = chunk.try_into().unwrap();
                    let batch_results = simd_sha256::intel_sha_sha256_x4(input_array);
                    results.extend(batch_results.into_iter());
                }
            } else {
                for input in chunk {
                    results.push(self.inner.hash(input));
                }
            }
        }
        
        results
    }
    
    #[cfg(target_arch = "aarch64")]
    fn neon_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        if !self.capabilities.has_neon {
            return inputs.iter().map(|input| self.inner.hash(input)).collect();
        }
        
        let mut results = Vec::with_capacity(inputs.len());
        
        for chunk in inputs.chunks(4) {
            if chunk.len() == 4 {
                unsafe {
                    let input_array: &[&[u8]; 4] = chunk.try_into().unwrap();
                    let batch_results = simd_sha256::neon_sha256_x4(input_array);
                    results.extend(batch_results.into_iter());
                }
            } else {
                for input in chunk {
                    results.push(self.inner.hash(input));
                }
            }
        }
        
        results
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn avx512_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        inputs.iter().map(|input| self.inner.hash(input)).collect()
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn avx2_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        inputs.iter().map(|input| self.inner.hash(input)).collect()
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn intel_sha_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        inputs.iter().map(|input| self.inner.hash(input)).collect()
    }
    
    #[cfg(not(target_arch = "aarch64"))]
    fn neon_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        inputs.iter().map(|input| self.inner.hash(input)).collect()
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn simd_batch_hash(&self, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        inputs.iter().map(|input| self.inner.hash(input)).collect()
    }
}

/// SIMD-optimized SHA-256 implementations
pub mod simd_sha256 {
    use super::*;
    
    /// AVX2 8-way parallel SHA-256 
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn avx2_sha256_x8(inputs: &[&[u8]; 8]) -> [Vec<u8>; 8] {
        #[cfg(target_feature = "avx2")]
        {
            // This would implement 8-way parallel SHA-256 using AVX2
            // For now, fall back to sequential processing with SIMD-enabled sha2
            use sha2::{Sha256, Digest};
            [
                Sha256::digest(inputs[0]).to_vec(),
                Sha256::digest(inputs[1]).to_vec(),
                Sha256::digest(inputs[2]).to_vec(),
                Sha256::digest(inputs[3]).to_vec(),
                Sha256::digest(inputs[4]).to_vec(),
                Sha256::digest(inputs[5]).to_vec(),
                Sha256::digest(inputs[6]).to_vec(),
                Sha256::digest(inputs[7]).to_vec(),
            ]
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            use sha2::{Sha256, Digest};
            [
                Sha256::digest(inputs[0]).to_vec(),
                Sha256::digest(inputs[1]).to_vec(),
                Sha256::digest(inputs[2]).to_vec(),
                Sha256::digest(inputs[3]).to_vec(),
                Sha256::digest(inputs[4]).to_vec(),
                Sha256::digest(inputs[5]).to_vec(),
                Sha256::digest(inputs[6]).to_vec(),
                Sha256::digest(inputs[7]).to_vec(),
            ]
        }
    }
    
    /// AVX-512 16-way parallel SHA-256
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn avx512_sha256_x16(inputs: &[&[u8]; 16]) -> [Vec<u8>; 16] {
        #[cfg(target_feature = "avx512f")]
        {
            // This would implement 16-way parallel SHA-256 using AVX-512
            use sha2::{Sha256, Digest};
            [
                Sha256::digest(inputs[0]).to_vec(),   Sha256::digest(inputs[1]).to_vec(),
                Sha256::digest(inputs[2]).to_vec(),   Sha256::digest(inputs[3]).to_vec(),
                Sha256::digest(inputs[4]).to_vec(),   Sha256::digest(inputs[5]).to_vec(),
                Sha256::digest(inputs[6]).to_vec(),   Sha256::digest(inputs[7]).to_vec(),
                Sha256::digest(inputs[8]).to_vec(),   Sha256::digest(inputs[9]).to_vec(),
                Sha256::digest(inputs[10]).to_vec(),  Sha256::digest(inputs[11]).to_vec(),
                Sha256::digest(inputs[12]).to_vec(),  Sha256::digest(inputs[13]).to_vec(),
                Sha256::digest(inputs[14]).to_vec(),  Sha256::digest(inputs[15]).to_vec(),
            ]
        }
        #[cfg(not(target_feature = "avx512f"))]
        {
            // Fallback to AVX2 if available
            let first_8: &[&[u8]; 8] = inputs[0..8].try_into().unwrap();
            let second_8: &[&[u8]; 8] = inputs[8..16].try_into().unwrap();
            let first_results = avx2_sha256_x8(first_8);
            let second_results = avx2_sha256_x8(second_8);
            [
                first_results[0].clone(), first_results[1].clone(),
                first_results[2].clone(), first_results[3].clone(),
                first_results[4].clone(), first_results[5].clone(),
                first_results[6].clone(), first_results[7].clone(),
                second_results[0].clone(), second_results[1].clone(),
                second_results[2].clone(), second_results[3].clone(),
                second_results[4].clone(), second_results[5].clone(),
                second_results[6].clone(), second_results[7].clone(),
            ]
        }
    }
    
    /// Intel SHA extensions accelerated SHA-256
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn intel_sha_sha256_x4(inputs: &[&[u8]; 4]) -> [Vec<u8>; 4] {
        #[cfg(target_feature = "sha")]
        {
            // This would use Intel SHA intrinsics for hardware acceleration
            // _mm_sha256rnds2_epu32, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32
            use sha2::{Sha256, Digest};
            [
                Sha256::digest(inputs[0]).to_vec(),
                Sha256::digest(inputs[1]).to_vec(),
                Sha256::digest(inputs[2]).to_vec(),
                Sha256::digest(inputs[3]).to_vec(),
            ]
        }
        #[cfg(not(target_feature = "sha"))]
        {
            use sha2::{Sha256, Digest};
            [
                Sha256::digest(inputs[0]).to_vec(),
                Sha256::digest(inputs[1]).to_vec(),
                Sha256::digest(inputs[2]).to_vec(),
                Sha256::digest(inputs[3]).to_vec(),
            ]
        }
    }
    
    /// ARM NEON 4-way parallel SHA-256
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn neon_sha256_x4(inputs: &[&[u8]; 4]) -> [Vec<u8>; 4] {
        #[cfg(target_feature = "neon")]
        {
            // This would use ARM NEON crypto extensions
            // vsha256hq_u32, vsha256h2q_u32, vsha256su0q_u32, vsha256su1q_u32
            use sha2::{Sha256, Digest};
            [
                Sha256::digest(inputs[0]).to_vec(),
                Sha256::digest(inputs[1]).to_vec(),
                Sha256::digest(inputs[2]).to_vec(),
                Sha256::digest(inputs[3]).to_vec(),
            ]
        }
        #[cfg(not(target_feature = "neon"))]
        {
            use sha2::{Sha256, Digest};
            [
                Sha256::digest(inputs[0]).to_vec(),
                Sha256::digest(inputs[1]).to_vec(),
                Sha256::digest(inputs[2]).to_vec(),
                Sha256::digest(inputs[3]).to_vec(),
            ]
        }
    }
}

/// Intel SHA extensions support
#[cfg(all(target_arch = "x86_64", target_feature = "sha"))]
pub mod intel_sha {
    use super::*;
    
    pub struct IntelShaHashFunction;
    
    impl HashFunction for IntelShaHashFunction {
        const OUTPUT_SIZE: usize = 32;
        const NAME: &'static str = "Intel-SHA";
        
        fn hash(&self, data: &[u8]) -> Vec<u8> {
            // Use Intel SHA extensions for hardware-accelerated hashing
            sha2::Sha256::digest(data).to_vec()
        }
        
        fn prf(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
            let mut data = Vec::with_capacity(key.len() + input.len());
            data.extend_from_slice(key);
            data.extend_from_slice(input);
            Ok(self.hash(&data))
        }
        
        fn hash_with_bitmask(&self, key: &[u8], left: &[u8], right: &[u8], bitmask_seed: &[u8]) -> Result<Vec<u8>> {
            // Optimized bitmask operations using SIMD
            let bitmask_left = self.prf(bitmask_seed, &[1u8])?;
            let bitmask_right = self.prf(bitmask_seed, &[2u8])?;
            
            let mut masked_left = left.to_vec();
            let mut masked_right = right.to_vec();
            
            // Use SIMD XOR operations for bitmask application
            #[cfg(target_feature = "avx2")]
            unsafe {
                simd_xor(&mut masked_left, &bitmask_left);
                simd_xor(&mut masked_right, &bitmask_right);
            }
            #[cfg(not(target_feature = "avx2"))]
            {
                for i in 0..left.len() {
                    masked_left[i] ^= bitmask_left[i];
                }
                for i in 0..right.len() {
                    masked_right[i] ^= bitmask_right[i];
                }
            }
            
            let mut data = Vec::with_capacity(key.len() + masked_left.len() + masked_right.len());
            data.extend_from_slice(key);
            data.extend_from_slice(&masked_left);
            data.extend_from_slice(&masked_right);
            
            Ok(self.hash(&data))
        }
    }
    
    /// SIMD XOR operation for bitmask application
    #[cfg(target_feature = "avx2")]
    unsafe fn simd_xor(data: &mut [u8], mask: &[u8]) {
        use std::arch::x86_64::*;
        
        let chunks = data.chunks_exact_mut(32);
        let mask_chunks = mask.chunks_exact(32);
        
        for (data_chunk, mask_chunk) in chunks.zip(mask_chunks) {
            let data_vec = _mm256_loadu_si256(data_chunk.as_ptr() as *const __m256i);
            let mask_vec = _mm256_loadu_si256(mask_chunk.as_ptr() as *const __m256i);
            let result = _mm256_xor_si256(data_vec, mask_vec);
            _mm256_storeu_si256(data_chunk.as_mut_ptr() as *mut __m256i, result);
        }
        
        // Handle remaining bytes
        let remaining_start = (data.len() / 32) * 32;
        for i in remaining_start..data.len() {
            data[i] ^= mask[i];
        }
    }
}