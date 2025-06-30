//! Mobile platform optimizations for CryptKeyPer
//! 
//! This module provides optimizations specifically for mobile and embedded
//! devices, including ARM processors with NEON extensions.

pub mod arm_neon;
pub mod power_management;
pub mod memory_optimization;

use crate::errors::Result;
use crate::parameters::XmssParameterSet;

/// Mobile-optimized XMSS configuration
#[derive(Debug, Clone)]
pub struct MobileXmssConfig {
    /// Parameter set optimized for mobile constraints
    pub parameter_set: XmssParameterSet,
    /// Use NEON acceleration if available
    pub use_neon: bool,
    /// Power-aware computation scheduling
    pub power_efficient: bool,
    /// Memory usage limits (MB)
    pub max_memory_mb: f64,
    /// Battery usage optimization
    pub optimize_for_battery: bool,
}

impl Default for MobileXmssConfig {
    fn default() -> Self {
        Self {
            parameter_set: XmssParameterSet::XmssSha256W16H10, // Small parameter set for mobile
            use_neon: true,
            power_efficient: true,
            max_memory_mb: 50.0, // Conservative memory usage
            optimize_for_battery: true,
        }
    }
}

impl MobileXmssConfig {
    /// Create configuration optimized for smartphones
    pub fn smartphone() -> Self {
        Self {
            parameter_set: XmssParameterSet::XmssSha256W16H16, // Medium security
            use_neon: true,
            power_efficient: true,
            max_memory_mb: 100.0,
            optimize_for_battery: true,
        }
    }
    
    /// Create configuration optimized for IoT devices
    pub fn iot_device() -> Self {
        Self {
            parameter_set: XmssParameterSet::XmssSha256W16H10, // Minimal security
            use_neon: false, // Many IoT devices don't have NEON
            power_efficient: true,
            max_memory_mb: 10.0, // Very constrained
            optimize_for_battery: true,
        }
    }
    
    /// Create configuration for tablets/high-end devices
    pub fn tablet() -> Self {
        Self {
            parameter_set: XmssParameterSet::XmssSha256W16H20, // Higher security
            use_neon: true,
            power_efficient: false, // More performance
            max_memory_mb: 200.0,
            optimize_for_battery: false,
        }
    }
    
    /// Create configuration for embedded cryptographic modules
    pub fn embedded_secure() -> Self {
        Self {
            parameter_set: XmssParameterSet::XmssSha512W16H16, // High security
            use_neon: detect_neon_support(),
            power_efficient: true,
            max_memory_mb: 25.0,
            optimize_for_battery: true,
        }
    }
}

/// Mobile platform detection and capabilities
#[derive(Debug, Clone)]
pub struct MobilePlatform {
    pub architecture: MobileArch,
    pub has_neon: bool,
    pub has_crypto_extensions: bool,
    pub core_count: u8,
    pub memory_mb: u32,
    pub is_battery_powered: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MobileArch {
    Armv7,
    Armv8A32, // AArch32 on ARMv8
    Armv8A64, // AArch64
    Armv9,
    Unknown,
}

impl MobilePlatform {
    /// Detect the current mobile platform capabilities
    pub fn detect() -> Self {
        Self {
            architecture: detect_arm_architecture(),
            has_neon: detect_neon_support(),
            has_crypto_extensions: detect_crypto_extensions(),
            core_count: detect_core_count(),
            memory_mb: detect_memory_size(),
            is_battery_powered: detect_battery_power(),
        }
    }
    
    /// Get recommended XMSS configuration for this platform
    pub fn recommended_config(&self) -> MobileXmssConfig {
        match (self.memory_mb, self.core_count, self.has_neon) {
            // High-end devices (>4GB RAM, 8+ cores)
            (mem, cores, _) if mem > 4000 && cores >= 8 => MobileXmssConfig::tablet(),
            
            // Smartphones (1-4GB RAM, 4+ cores, NEON)
            (mem, cores, true) if mem > 1000 && cores >= 4 => MobileXmssConfig::smartphone(),
            
            // Lower-end devices or embedded
            (mem, _, neon) if mem < 1000 => {
                let mut config = MobileXmssConfig::iot_device();
                config.use_neon = neon;
                config.max_memory_mb = (mem as f64 * 0.1).min(50.0); // Use max 10% of RAM
                config
            },
            
            // Default for everything else
            _ => MobileXmssConfig::default(),
        }
    }
    
    /// Check if this platform supports hardware-accelerated cryptography
    pub fn supports_hw_crypto(&self) -> bool {
        self.has_crypto_extensions && matches!(
            self.architecture, 
            MobileArch::Armv8A64 | MobileArch::Armv9
        )
    }
    
    /// Estimate relative performance compared to desktop CPU
    pub fn relative_performance(&self) -> f64 {
        let base_score = match self.architecture {
            MobileArch::Armv9 => 1.0,
            MobileArch::Armv8A64 => 0.8,
            MobileArch::Armv8A32 => 0.6,
            MobileArch::Armv7 => 0.4,
            MobileArch::Unknown => 0.3,
        };
        
        let neon_multiplier = if self.has_neon { 1.5 } else { 1.0 };
        let crypto_multiplier = if self.has_crypto_extensions { 1.3 } else { 1.0 };
        let core_multiplier = (self.core_count as f64 / 4.0).min(2.0);
        
        base_score * neon_multiplier * crypto_multiplier * core_multiplier
    }
}

/// Mobile-specific performance benchmarks
#[derive(Debug, Clone)]
pub struct MobileBenchmark {
    pub platform: MobilePlatform,
    pub config: MobileXmssConfig,
    pub keygen_time_ms: f64,
    pub sign_time_ms: f64,
    pub verify_time_ms: f64,
    pub memory_usage_mb: f64,
    pub battery_impact_score: f64, // 0-10 scale
}

impl MobileBenchmark {
    /// Run performance benchmark on current platform
    pub fn run(config: MobileXmssConfig) -> Result<Self> {
        let platform = MobilePlatform::detect();
        
        // Estimate performance based on platform capabilities
        let base_performance = platform.relative_performance();
        let neon_speedup = if config.use_neon && platform.has_neon { 2.0 } else { 1.0 };
        
        // Estimated timings (would be real benchmarks in production)
        let keygen_time_ms = (100.0 / base_performance / neon_speedup) 
            * if config.power_efficient { 1.2 } else { 1.0 };
        let sign_time_ms = (50.0 / base_performance / neon_speedup)
            * if config.power_efficient { 1.1 } else { 1.0 };
        let verify_time_ms = (25.0 / base_performance / neon_speedup);
        
        let memory_usage_mb = config.max_memory_mb * 0.7; // Typical usage
        
        let battery_impact_score = calculate_battery_impact(
            &platform, 
            &config, 
            keygen_time_ms, 
            sign_time_ms
        );
        
        Ok(Self {
            platform,
            config,
            keygen_time_ms,
            sign_time_ms,
            verify_time_ms,
            memory_usage_mb,
            battery_impact_score,
        })
    }
    
    /// Check if performance meets mobile requirements
    pub fn meets_mobile_requirements(&self) -> MobileCompatibility {
        let mut issues = Vec::new();
        let mut score = 10.0;
        
        // Check timing requirements
        if self.sign_time_ms > 100.0 {
            issues.push("Signing too slow for interactive use".to_string());
            score -= 3.0;
        }
        
        if self.verify_time_ms > 50.0 {
            issues.push("Verification too slow for real-time apps".to_string());
            score -= 2.0;
        }
        
        // Check memory requirements
        if self.memory_usage_mb > self.config.max_memory_mb {
            issues.push("Memory usage exceeds mobile constraints".to_string());
            score -= 4.0;
        }
        
        // Check battery impact
        if self.battery_impact_score > 7.0 {
            issues.push("High battery drain unsuitable for mobile".to_string());
            score -= 2.0;
        }
        
        let compatibility = if score >= 8.0 {
            MobileCompatibilityLevel::Excellent
        } else if score >= 6.0 {
            MobileCompatibilityLevel::Good
        } else if score >= 4.0 {
            MobileCompatibilityLevel::Acceptable
        } else {
            MobileCompatibilityLevel::Poor
        };
        
        MobileCompatibility {
            level: compatibility,
            score: score.max(0.0),
            issues,
            recommendations: generate_recommendations(&self),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MobileCompatibility {
    pub level: MobileCompatibilityLevel,
    pub score: f64,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MobileCompatibilityLevel {
    Excellent,
    Good, 
    Acceptable,
    Poor,
}

// Platform detection functions
fn detect_arm_architecture() -> MobileArch {
    #[cfg(target_arch = "aarch64")]
    {
        // Check for ARMv9 features if available
        if std::arch::is_aarch64_feature_detected!("sve") {
            MobileArch::Armv9
        } else {
            MobileArch::Armv8A64
        }
    }
    
    #[cfg(target_arch = "arm")]
    {
        // Check for ARMv8 in AArch32 mode vs ARMv7
        if std::arch::is_arm_feature_detected!("v8") {
            MobileArch::Armv8A32
        } else {
            MobileArch::Armv7
        }
    }
    
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    {
        MobileArch::Unknown
    }
}

fn detect_neon_support() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        true // NEON is mandatory on AArch64
    }
    
    #[cfg(target_arch = "arm")]
    {
        std::arch::is_arm_feature_detected!("neon")
    }
    
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    {
        false
    }
}

fn detect_crypto_extensions() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes") && 
        std::arch::is_aarch64_feature_detected!("sha2")
    }
    
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

fn detect_core_count() -> u8 {
    std::thread::available_parallelism()
        .map(|p| p.get() as u8)
        .unwrap_or(4)
}

fn detect_memory_size() -> u32 {
    // In a real implementation, this would query system memory
    // For now, return a reasonable default
    2048 // 2GB
}

fn detect_battery_power() -> bool {
    // In a real implementation, this would check if device is battery-powered
    // Mobile platforms are typically battery-powered
    true
}

fn calculate_battery_impact(
    platform: &MobilePlatform, 
    config: &MobileXmssConfig,
    keygen_time_ms: f64,
    sign_time_ms: f64
) -> f64 {
    let base_impact = if config.optimize_for_battery { 3.0 } else { 6.0 };
    
    // Longer operations drain more battery
    let time_impact = (keygen_time_ms + sign_time_ms * 10.0) / 100.0;
    
    // More cores can parallelize but use more power
    let core_impact = (platform.core_count as f64 - 4.0) * 0.5;
    
    // NEON can be more efficient but uses more power
    let neon_impact = if config.use_neon && platform.has_neon { -0.5 } else { 0.0 };
    
    (base_impact + time_impact + core_impact + neon_impact).clamp(0.0, 10.0)
}

fn generate_recommendations(benchmark: &MobileBenchmark) -> Vec<String> {
    let mut recommendations = Vec::new();
    
    if benchmark.sign_time_ms > 50.0 {
        recommendations.push("Consider using a smaller parameter set for better performance".to_string());
    }
    
    if benchmark.memory_usage_mb > benchmark.config.max_memory_mb * 0.8 {
        recommendations.push("Enable memory optimization features".to_string());
    }
    
    if benchmark.battery_impact_score > 6.0 {
        recommendations.push("Enable power-efficient mode to reduce battery drain".to_string());
    }
    
    if benchmark.platform.has_neon && !benchmark.config.use_neon {
        recommendations.push("Enable NEON acceleration for better performance".to_string());
    }
    
    if benchmark.platform.has_crypto_extensions {
        recommendations.push("Consider using hardware crypto extensions if available".to_string());
    }
    
    recommendations
}