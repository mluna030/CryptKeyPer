use crate::hash_traits::{HashFunction, HashFunctionType, Sha256HashFunction, Sha512HashFunction, Shake128HashFunction};
use crate::errors::{CryptKeyperError, Result};

/// XMSS Parameter Sets following RFC 8391 and NIST recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmssParameterSet {
    // SHA-256 based parameter sets
    XmssSha256W16H10,
    XmssSha256W16H16,
    XmssSha256W16H20,
    
    // SHA-512 based parameter sets  
    XmssSha512W16H10,
    XmssSha512W16H16,
    XmssSha512W16H20,
    
    // SHAKE128 based parameter sets
    XmssShake128W16H10,
    XmssShake128W16H16,
    XmssShake128W16H20,
}

impl XmssParameterSet {
    /// Get the Winternitz parameter for this parameter set
    pub fn winternitz_parameter(self) -> u32 {
        match self {
            // All current parameter sets use W=16
            _ => 16,
        }
    }
    
    /// Get the tree height for this parameter set
    pub fn tree_height(self) -> u32 {
        match self {
            Self::XmssSha256W16H10 | Self::XmssSha512W16H10 | Self::XmssShake128W16H10 => 10,
            Self::XmssSha256W16H16 | Self::XmssSha512W16H16 | Self::XmssShake128W16H16 => 16,
            Self::XmssSha256W16H20 | Self::XmssSha512W16H20 | Self::XmssShake128W16H20 => 20,
        }
    }
    
    /// Get the maximum number of signatures for this parameter set
    pub fn max_signatures(self) -> u64 {
        1u64 << self.tree_height()
    }
    
    /// Get the hash output size in bytes
    pub fn hash_size(self) -> usize {
        match self {
            Self::XmssSha256W16H10 | Self::XmssSha256W16H16 | Self::XmssSha256W16H20 => 32,
            Self::XmssSha512W16H10 | Self::XmssSha512W16H16 | Self::XmssSha512W16H20 => 64,
            Self::XmssShake128W16H10 | Self::XmssShake128W16H16 | Self::XmssShake128W16H20 => 32,
        }
    }
    
    /// Get the WOTS+ parameters for this parameter set
    pub fn wots_params(self) -> WotsParameters {
        let w = self.winternitz_parameter();
        let log_w = match w {
            4 => 2,
            16 => 4,
            256 => 8,
            _ => 4, // Default to 4
        };
        
        // For 256-bit hash output (32 bytes)
        let len1 = if self.hash_size() == 32 {
            (8 * 32 + log_w - 1) / log_w  // ceil(256 / log_w)
        } else {
            (8 * 64 + log_w - 1) / log_w  // ceil(512 / log_w) for SHA-512
        };
        
        let len2 = {
            let max_checksum = len1 * (w - 1);
            ((log_w as f64) * (max_checksum as f64).log2().ceil()).ceil() as u32 / log_w + 1
        };
        
        WotsParameters {
            w,
            log_w,
            len1: len1 as usize,
            len2: len2 as usize,
            len: (len1 + len2) as usize,
        }
    }
    
    /// Get a description of this parameter set
    pub fn description(self) -> &'static str {
        match self {
            Self::XmssSha256W16H10 => "XMSS-SHA2_256-W16-H10",
            Self::XmssSha256W16H16 => "XMSS-SHA2_256-W16-H16", 
            Self::XmssSha256W16H20 => "XMSS-SHA2_256-W16-H20",
            Self::XmssSha512W16H10 => "XMSS-SHA2_512-W16-H10",
            Self::XmssSha512W16H16 => "XMSS-SHA2_512-W16-H16",
            Self::XmssSha512W16H20 => "XMSS-SHA2_512-W16-H20",
            Self::XmssShake128W16H10 => "XMSS-SHAKE128-W16-H10",
            Self::XmssShake128W16H16 => "XMSS-SHAKE128-W16-H16",
            Self::XmssShake128W16H20 => "XMSS-SHAKE128-W16-H20",
        }
    }
    
    /// Create a hash function instance for this parameter set
    pub fn create_hash_function(self) -> HashFunctionType {
        match self {
            Self::XmssSha256W16H10 | Self::XmssSha256W16H16 | Self::XmssSha256W16H20 => {
                HashFunctionType::Sha256(Sha256HashFunction)
            }
            Self::XmssSha512W16H10 | Self::XmssSha512W16H16 | Self::XmssSha512W16H20 => {
                HashFunctionType::Sha512(Sha512HashFunction)
            }
            Self::XmssShake128W16H10 | Self::XmssShake128W16H16 | Self::XmssShake128W16H20 => {
                HashFunctionType::Shake128(Shake128HashFunction)
            }
        }
    }
}

/// WOTS+ parameters derived from XMSS parameter set
#[derive(Debug, Clone, Copy)]
pub struct WotsParameters {
    /// Winternitz parameter (trade-off between signature size and security)
    pub w: u32,
    /// log2(w)
    pub log_w: u32,
    /// Number of chains for message (ceil(hash_bitlen / log_w))
    pub len1: usize,
    /// Number of chains for checksum
    pub len2: usize,
    /// Total number of chains (len1 + len2)
    pub len: usize,
}

impl WotsParameters {
    /// Calculate checksum for base-w representation
    pub fn calculate_checksum(&self, message_base_w: &[u32]) -> Vec<u32> {
        let mut checksum = 0u32;
        
        // Calculate checksum
        for &digit in message_base_w {
            checksum += self.w - 1 - digit;
        }
        
        // Convert checksum to base-w
        let mut checksum_base_w = Vec::new();
        let mut temp_checksum = checksum;
        
        for _ in 0..self.len2 {
            checksum_base_w.push(temp_checksum % self.w);
            temp_checksum /= self.w;
        }
        
        checksum_base_w
    }
    
    /// Convert message to base-w representation
    pub fn message_to_base_w(&self, message: &[u8]) -> Vec<u32> {
        let mut result = Vec::with_capacity(self.len1);
        
        for byte in message {
            let mut b = *byte;
            for _ in 0..(8 / self.log_w) {
                if result.len() >= self.len1 {
                    break;
                }
                let digit = (b & ((1 << self.log_w) - 1)) as u32;
                result.push(digit);
                b >>= self.log_w;
            }
        }
        
        // Pad with zeros if necessary
        while result.len() < self.len1 {
            result.push(0);
        }
        
        result
    }
    
    /// Convert message to full base-w representation including checksum
    pub fn message_to_base_w_with_checksum(&self, message: &[u8]) -> Vec<u32> {
        let message_base_w = self.message_to_base_w(message);
        let checksum_base_w = self.calculate_checksum(&message_base_w);
        
        let mut result = message_base_w;
        result.extend(checksum_base_w);
        result
    }
}

/// Multi-tree XMSS parameter sets (XMSS^MT)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmssMtParameterSet {
    // SHA-256 based MT parameter sets
    XmssMtSha256W16H20D2,  // Height 20, 2 layers
    XmssMtSha256W16H20D4,  // Height 20, 4 layers
    XmssMtSha256W16H40D2,  // Height 40, 2 layers
    XmssMtSha256W16H40D4,  // Height 40, 4 layers
    XmssMtSha256W16H40D8,  // Height 40, 8 layers
    XmssMtSha256W16H60D3,  // Height 60, 3 layers
    XmssMtSha256W16H60D6,  // Height 60, 6 layers
    XmssMtSha256W16H60D12, // Height 60, 12 layers
}

impl XmssMtParameterSet {
    /// Get the total tree height
    pub fn total_height(self) -> u32 {
        match self {
            Self::XmssMtSha256W16H20D2 | Self::XmssMtSha256W16H20D4 => 20,
            Self::XmssMtSha256W16H40D2 | Self::XmssMtSha256W16H40D4 | Self::XmssMtSha256W16H40D8 => 40,
            Self::XmssMtSha256W16H60D3 | Self::XmssMtSha256W16H60D6 | Self::XmssMtSha256W16H60D12 => 60,
        }
    }
    
    /// Get the number of layers (d parameter)
    pub fn layers(self) -> u32 {
        match self {
            Self::XmssMtSha256W16H20D2 | Self::XmssMtSha256W16H40D2 => 2,
            Self::XmssMtSha256W16H60D3 => 3,
            Self::XmssMtSha256W16H20D4 | Self::XmssMtSha256W16H40D4 => 4,
            Self::XmssMtSha256W16H60D6 => 6,
            Self::XmssMtSha256W16H40D8 => 8,
            Self::XmssMtSha256W16H60D12 => 12,
        }
    }
    
    /// Get the height of each individual tree
    pub fn tree_height(self) -> u32 {
        self.total_height() / self.layers()
    }
    
    /// Get the maximum number of signatures
    pub fn max_signatures(self) -> u128 {
        1u128 << self.total_height()
    }
    
    /// Get a description of this parameter set
    pub fn description(self) -> &'static str {
        match self {
            Self::XmssMtSha256W16H20D2 => "XMSSMT-SHA2_256-W16-H20-D2",
            Self::XmssMtSha256W16H20D4 => "XMSSMT-SHA2_256-W16-H20-D4",
            Self::XmssMtSha256W16H40D2 => "XMSSMT-SHA2_256-W16-H40-D2",
            Self::XmssMtSha256W16H40D4 => "XMSSMT-SHA2_256-W16-H40-D4",
            Self::XmssMtSha256W16H40D8 => "XMSSMT-SHA2_256-W16-H40-D8",
            Self::XmssMtSha256W16H60D3 => "XMSSMT-SHA2_256-W16-H60-D3",
            Self::XmssMtSha256W16H60D6 => "XMSSMT-SHA2_256-W16-H60-D6",
            Self::XmssMtSha256W16H60D12 => "XMSSMT-SHA2_256-W16-H60-D12",
        }
    }
}