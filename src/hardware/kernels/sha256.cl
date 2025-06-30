/*
 * OpenCL SHA-256 kernel for massively parallel hashing
 * Optimized for XMSS hash tree computation
 */

// SHA-256 constants
__constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 initial hash values
__constant uint H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Rotate right
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 functions
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/**
 * Parallel SHA-256 kernel
 * Each work item processes one hash computation
 * 
 * @param input_data: Flattened input data for all hash computations
 * @param input_lengths: Length of each input in bytes
 * @param output_hashes: Output buffer for computed hashes (32 bytes each)
 * @param num_hashes: Total number of hash computations
 */
__kernel void parallel_sha256(
    __global const uchar* input_data,
    __global const uint* input_offsets,
    __global const uint* input_lengths,
    __global uchar* output_hashes,
    uint num_hashes
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_hashes) {
        return;
    }
    
    // Get input for this work item
    uint input_offset = input_offsets[gid];
    uint input_length = input_lengths[gid];
    __global const uchar* input = input_data + input_offset;
    
    // Initialize hash state
    uint h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = H0[i];
    }
    
    // Process input in 512-bit (64-byte) chunks
    uint num_chunks = (input_length + 8 + 64) / 64; // +8 for length, round up
    
    for (uint chunk = 0; chunk < num_chunks; chunk++) {
        uint w[64];
        
        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            uint word = 0;
            for (int j = 0; j < 4; j++) {
                uint byte_idx = chunk * 64 + i * 4 + j;
                uchar byte_val = 0;
                
                if (byte_idx < input_length) {
                    byte_val = input[byte_idx];
                } else if (byte_idx == input_length) {
                    byte_val = 0x80; // Padding bit
                } else if (byte_idx >= chunk * 64 + 56 && byte_idx < chunk * 64 + 64) {
                    // Length in bits in last 8 bytes (big-endian)
                    uint bit_length = input_length * 8;
                    int shift = (7 - (byte_idx - (chunk * 64 + 56))) * 8;
                    byte_val = (bit_length >> shift) & 0xFF;
                }
                
                word = (word << 8) | byte_val;
            }
            w[i] = word;
        }
        
        // Extend message schedule
        for (int i = 16; i < 64; i++) {
            w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
        }
        
        // Initialize working variables
        uint a = h[0], b = h[1], c = h[2], d = h[3];
        uint e = h[4], f = h[5], g = h[6], h_var = h[7];
        
        // Main loop
        for (int i = 0; i < 64; i++) {
            uint t1 = h_var + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
            uint t2 = SIGMA0(a) + MAJ(a, b, c);
            
            h_var = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        // Update hash state
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_var;
    }
    
    // Write output (convert to big-endian bytes)
    __global uchar* output = output_hashes + gid * 32;
    for (int i = 0; i < 8; i++) {
        uint word = h[i];
        output[i*4 + 0] = (word >> 24) & 0xFF;
        output[i*4 + 1] = (word >> 16) & 0xFF;
        output[i*4 + 2] = (word >> 8) & 0xFF;
        output[i*4 + 3] = word & 0xFF;
    }
}

/**
 * Optimized kernel for XMSS WOTS+ chain computation
 * Performs iterative hashing for hash chains
 */
__kernel void wots_hash_chain(
    __global const uchar* input_seeds,
    __global const uchar* address_bytes,
    __global uchar* output_chains,
    uint chain_length,
    uint num_chains
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_chains) {
        return;
    }
    
    // Get input seed and address for this chain
    __global const uchar* seed = input_seeds + gid * 32;
    __global const uchar* address = address_bytes + gid * 32;
    __global uchar* output = output_chains + gid * 32;
    
    // Copy seed to working buffer
    uchar current[32];
    for (int i = 0; i < 32; i++) {
        current[i] = seed[i];
    }
    
    // Perform hash chain computation
    for (uint iteration = 0; iteration < chain_length; iteration++) {
        // Prepare input: address || current_value
        uchar hash_input[64];
        for (int i = 0; i < 32; i++) {
            hash_input[i] = address[i];
            hash_input[32 + i] = current[i];
        }
        
        // Compute SHA-256 hash
        // (This would use the same SHA-256 logic as above)
        // For brevity, assuming a sha256_hash function exists
        sha256_single(hash_input, 64, current);
    }
    
    // Copy final result to output
    for (int i = 0; i < 32; i++) {
        output[i] = current[i];
    }
}

/**
 * Single SHA-256 computation helper
 */
void sha256_single(__global const uchar* input, uint length, uchar* output) {
    // Initialize hash state
    uint h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = H0[i];
    }
    
    // Process message (simplified for fixed 64-byte input)
    uint w[64];
    
    // Load input into message schedule
    for (int i = 0; i < 16; i++) {
        uint word = 0;
        for (int j = 0; j < 4; j++) {
            uint byte_idx = i * 4 + j;
            uchar byte_val = (byte_idx < length) ? input[byte_idx] : 
                           (byte_idx == length) ? 0x80 : 0;
            word = (word << 8) | byte_val;
        }
        w[i] = word;
    }
    
    // Add length in last two words (for 64-byte input)
    w[14] = 0; // High bits of length
    w[15] = length * 8; // Length in bits
    
    // Extend message schedule
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    
    // Process message
    uint a = h[0], b = h[1], c = h[2], d = h[3];
    uint e = h[4], f = h[5], g = h[6], h_var = h[7];
    
    for (int i = 0; i < 64; i++) {
        uint t1 = h_var + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
        uint t2 = SIGMA0(a) + MAJ(a, b, c);
        
        h_var = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    // Update hash state
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_var;
    
    // Convert to bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        uint word = h[i];
        output[i*4 + 0] = (word >> 24) & 0xFF;
        output[i*4 + 1] = (word >> 16) & 0xFF;
        output[i*4 + 2] = (word >> 8) & 0xFF;
        output[i*4 + 3] = word & 0xFF;
    }
}