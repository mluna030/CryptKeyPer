//! Power management and battery optimization for mobile devices

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use crate::errors::Result;

/// Power-aware cryptographic operations manager
pub struct PowerManager {
    battery_level: AtomicU64, // Percentage * 100 for precision
    power_mode: PowerMode,
    thermal_state: ThermalState,
    operation_history: OperationHistory,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PowerMode {
    /// Maximum performance, ignore power consumption
    Performance,
    /// Balanced performance and power consumption
    Balanced,
    /// Minimize power consumption, accept slower performance
    PowerSaver,
    /// Critical battery level, minimal operations only
    Emergency,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalState {
    Normal,
    Warm,
    Hot,
    Critical,
}

#[derive(Debug, Clone)]
struct OperationHistory {
    recent_operations: Vec<OperationRecord>,
    total_energy_used: f64, // mJ (millijoules)
    start_time: Instant,
}

#[derive(Debug, Clone)]
struct OperationRecord {
    operation_type: OperationType,
    duration: Duration,
    estimated_energy: f64, // mJ
    timestamp: Instant,
}

#[derive(Debug, Clone, Copy)]
enum OperationType {
    KeyGeneration,
    Signing,
    Verification,
    HashComputation,
}

impl PowerManager {
    pub fn new() -> Self {
        Self {
            battery_level: AtomicU64::new(10000), // 100.00%
            power_mode: PowerMode::Balanced,
            thermal_state: ThermalState::Normal,
            operation_history: OperationHistory {
                recent_operations: Vec::new(),
                total_energy_used: 0.0,
                start_time: Instant::now(),
            },
        }
    }
    
    /// Update battery level (0.0 to 100.0)
    pub fn update_battery_level(&self, level: f64) {
        let level_scaled = (level * 100.0).round() as u64;
        self.battery_level.store(level_scaled.min(10000), Ordering::Relaxed);
    }
    
    /// Get current battery level as percentage
    pub fn battery_level(&self) -> f64 {
        self.battery_level.load(Ordering::Relaxed) as f64 / 100.0
    }
    
    /// Update power mode based on current conditions
    pub fn update_power_mode(&mut self) -> PowerMode {
        let battery = self.battery_level();
        
        self.power_mode = match (battery, self.thermal_state) {
            // Critical battery
            (level, _) if level < 5.0 => PowerMode::Emergency,
            
            // Low battery or hot device
            (level, ThermalState::Hot | ThermalState::Critical) if level < 20.0 => PowerMode::PowerSaver,
            (level, _) if level < 15.0 => PowerMode::PowerSaver,
            
            // Thermal throttling
            (_, ThermalState::Critical) => PowerMode::PowerSaver,
            (_, ThermalState::Hot) => PowerMode::Balanced,
            
            // High battery and normal thermal
            (level, ThermalState::Normal) if level > 50.0 => PowerMode::Performance,
            
            // Default to balanced
            _ => PowerMode::Balanced,
        };
        
        self.power_mode
    }
    
    /// Get power-aware operation parameters
    pub fn operation_parameters(&self) -> PowerAwareParams {
        match self.power_mode {
            PowerMode::Performance => PowerAwareParams {
                max_cpu_usage: 1.0,
                use_all_cores: true,
                use_simd: true,
                batch_size: 16,
                memory_cache_size: 100 * 1024 * 1024, // 100MB
                allow_background_tasks: true,
                operation_timeout_ms: 10000,
            },
            
            PowerMode::Balanced => PowerAwareParams {
                max_cpu_usage: 0.7,
                use_all_cores: true,
                use_simd: true,
                batch_size: 8,
                memory_cache_size: 50 * 1024 * 1024, // 50MB
                allow_background_tasks: true,
                operation_timeout_ms: 15000,
            },
            
            PowerMode::PowerSaver => PowerAwareParams {
                max_cpu_usage: 0.4,
                use_all_cores: false,
                use_simd: false, // Disable SIMD to save power
                batch_size: 4,
                memory_cache_size: 10 * 1024 * 1024, // 10MB
                allow_background_tasks: false,
                operation_timeout_ms: 30000,
            },
            
            PowerMode::Emergency => PowerAwareParams {
                max_cpu_usage: 0.2,
                use_all_cores: false,
                use_simd: false,
                batch_size: 1,
                memory_cache_size: 1 * 1024 * 1024, // 1MB
                allow_background_tasks: false,
                operation_timeout_ms: 60000,
            },
        }
    }
    
    /// Estimate energy cost of an operation
    pub fn estimate_energy_cost(&self, operation: CryptoOperation) -> EnergyEstimate {
        let base_cost = match operation.operation_type {
            OperationType::KeyGeneration => 50.0, // mJ
            OperationType::Signing => 25.0,
            OperationType::Verification => 10.0,
            OperationType::HashComputation => 5.0,
        };
        
        let params = self.operation_parameters();
        
        // Adjust for power mode
        let power_multiplier = match self.power_mode {
            PowerMode::Performance => 1.5, // Higher power for speed
            PowerMode::Balanced => 1.0,
            PowerMode::PowerSaver => 0.6, // Lower power, slower speed
            PowerMode::Emergency => 0.3,
        };
        
        // Adjust for SIMD usage
        let simd_multiplier = if params.use_simd { 1.2 } else { 1.0 };
        
        // Adjust for parallelism
        let parallel_multiplier = if params.use_all_cores { 
            1.3 // More cores = more power
        } else { 
            1.0 
        };
        
        let estimated_energy = base_cost * power_multiplier * simd_multiplier * parallel_multiplier;
        let estimated_time_ms = match self.power_mode {
            PowerMode::Performance => operation.complexity_factor * 10.0,
            PowerMode::Balanced => operation.complexity_factor * 15.0,
            PowerMode::PowerSaver => operation.complexity_factor * 30.0,
            PowerMode::Emergency => operation.complexity_factor * 60.0,
        };
        
        EnergyEstimate {
            energy_cost_mj: estimated_energy,
            estimated_time_ms,
            battery_drain_percent: estimated_energy / 36000.0, // Assume 10Wh battery
            thermal_impact: self.calculate_thermal_impact(estimated_energy),
            recommendation: self.get_recommendation(estimated_energy, estimated_time_ms),
        }
    }
    
    /// Check if operation should be allowed given current power state
    pub fn should_allow_operation(&self, operation: CryptoOperation) -> OperationDecision {
        let battery = self.battery_level();
        let estimate = self.estimate_energy_cost(operation.clone());
        
        // Critical battery - only allow essential operations
        if self.power_mode == PowerMode::Emergency {
            return if matches!(operation.operation_type, OperationType::Verification) {
                OperationDecision::Allow
            } else {
                OperationDecision::Deny {
                    reason: "Critical battery level - only verification allowed".to_string(),
                    suggested_delay: Some(Duration::from_secs(3600)), // Wait for charging
                }
            };
        }
        
        // Thermal protection
        if self.thermal_state == ThermalState::Critical {
            return OperationDecision::Delay {
                duration: Duration::from_secs(60),
                reason: "Device overheating - waiting for cool down".to_string(),
            };
        }
        
        // Check if operation would drain too much battery
        if estimate.battery_drain_percent > 1.0 && battery < 20.0 {
            return OperationDecision::Defer {
                reason: "Operation would drain significant battery".to_string(),
                alternative: "Consider using a smaller parameter set".to_string(),
            };
        }
        
        OperationDecision::Allow
    }
    
    /// Record completed operation for power analysis
    pub fn record_operation(&mut self, operation: OperationType, duration: Duration, actual_energy: f64) {
        let record = OperationRecord {
            operation_type: operation,
            duration,
            estimated_energy: actual_energy,
            timestamp: Instant::now(),
        };
        
        self.operation_history.recent_operations.push(record);
        self.operation_history.total_energy_used += actual_energy;
        
        // Keep only recent operations (last hour)
        let cutoff = Instant::now() - Duration::from_secs(3600);
        self.operation_history.recent_operations.retain(|op| op.timestamp > cutoff);
        
        // Update thermal state based on recent activity
        self.update_thermal_state();
    }
    
    /// Get power usage statistics
    pub fn power_statistics(&self) -> PowerStatistics {
        let recent_energy: f64 = self.operation_history.recent_operations
            .iter()
            .map(|op| op.estimated_energy)
            .sum();
        
        let operations_per_hour = self.operation_history.recent_operations.len() as f64;
        let average_energy_per_op = if operations_per_hour > 0.0 {
            recent_energy / operations_per_hour
        } else {
            0.0
        };
        
        PowerStatistics {
            total_energy_used_mj: self.operation_history.total_energy_used,
            recent_energy_used_mj: recent_energy,
            operations_per_hour,
            average_energy_per_operation: average_energy_per_op,
            current_power_mode: self.power_mode,
            thermal_state: self.thermal_state,
            battery_level_percent: self.battery_level(),
            efficiency_score: self.calculate_efficiency_score(),
        }
    }
    
    fn calculate_thermal_impact(&self, energy_mj: f64) -> ThermalImpact {
        match energy_mj {
            e if e < 10.0 => ThermalImpact::Minimal,
            e if e < 50.0 => ThermalImpact::Low,
            e if e < 100.0 => ThermalImpact::Moderate,
            _ => ThermalImpact::High,
        }
    }
    
    fn get_recommendation(&self, energy_mj: f64, time_ms: f64) -> PowerRecommendation {
        match (self.power_mode, energy_mj > 50.0, time_ms > 1000.0) {
            (PowerMode::Emergency, _, _) => PowerRecommendation::DeferUntilCharging,
            (PowerMode::PowerSaver, true, _) => PowerRecommendation::ReduceComplexity,
            (_, _, true) => PowerRecommendation::ConsiderBackground,
            _ => PowerRecommendation::ProceedNormally,
        }
    }
    
    fn update_thermal_state(&mut self) {
        // Simple thermal model based on recent activity
        let recent_energy: f64 = self.operation_history.recent_operations
            .iter()
            .filter(|op| op.timestamp > Instant::now() - Duration::from_secs(300)) // Last 5 minutes
            .map(|op| op.estimated_energy)
            .sum();
        
        self.thermal_state = match recent_energy {
            e if e < 100.0 => ThermalState::Normal,
            e if e < 500.0 => ThermalState::Warm,
            e if e < 1000.0 => ThermalState::Hot,
            _ => ThermalState::Critical,
        };
    }
    
    fn calculate_efficiency_score(&self) -> f64 {
        // Score from 0.0 to 10.0 based on power efficiency
        let base_score = match self.power_mode {
            PowerMode::Emergency => 2.0,
            PowerMode::PowerSaver => 8.0,
            PowerMode::Balanced => 6.0,
            PowerMode::Performance => 4.0,
        };
        
        let thermal_penalty = match self.thermal_state {
            ThermalState::Normal => 0.0,
            ThermalState::Warm => -1.0,
            ThermalState::Hot => -2.0,
            ThermalState::Critical => -4.0,
        };
        
        (base_score + thermal_penalty).max(0.0).min(10.0)
    }
}

#[derive(Debug, Clone)]
pub struct PowerAwareParams {
    pub max_cpu_usage: f64,
    pub use_all_cores: bool,
    pub use_simd: bool,
    pub batch_size: usize,
    pub memory_cache_size: usize,
    pub allow_background_tasks: bool,
    pub operation_timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CryptoOperation {
    pub operation_type: OperationType,
    pub complexity_factor: f64, // Relative complexity (1.0 = baseline)
    pub priority: OperationPriority,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OperationPriority {
    Critical,   // Must complete regardless of power state
    High,       // Important but can be delayed slightly
    Normal,     // Standard operations
    Low,        // Can be deferred or cancelled
    Background, // Run only when power is abundant
}

#[derive(Debug, Clone)]
pub struct EnergyEstimate {
    pub energy_cost_mj: f64,
    pub estimated_time_ms: f64,
    pub battery_drain_percent: f64,
    pub thermal_impact: ThermalImpact,
    pub recommendation: PowerRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalImpact {
    Minimal,
    Low,
    Moderate,
    High,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PowerRecommendation {
    ProceedNormally,
    ConsiderBackground,
    ReduceComplexity,
    DeferUntilCharging,
}

#[derive(Debug, Clone)]
pub enum OperationDecision {
    Allow,
    Delay { duration: Duration, reason: String },
    Defer { reason: String, alternative: String },
    Deny { reason: String, suggested_delay: Option<Duration> },
}

#[derive(Debug, Clone)]
pub struct PowerStatistics {
    pub total_energy_used_mj: f64,
    pub recent_energy_used_mj: f64,
    pub operations_per_hour: f64,
    pub average_energy_per_operation: f64,
    pub current_power_mode: PowerMode,
    pub thermal_state: ThermalState,
    pub battery_level_percent: f64,
    pub efficiency_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_power_mode_transitions() {
        let mut pm = PowerManager::new();
        
        // High battery should allow performance mode
        pm.update_battery_level(80.0);
        assert_eq!(pm.update_power_mode(), PowerMode::Performance);
        
        // Low battery should switch to power saver
        pm.update_battery_level(10.0);
        assert_eq!(pm.update_power_mode(), PowerMode::PowerSaver);
        
        // Critical battery should go to emergency
        pm.update_battery_level(3.0);
        assert_eq!(pm.update_power_mode(), PowerMode::Emergency);
    }
    
    #[test]
    fn test_operation_decisions() {
        let mut pm = PowerManager::new();
        pm.update_battery_level(5.0); // Critical battery
        pm.update_power_mode();
        
        let sign_op = CryptoOperation {
            operation_type: OperationType::Signing,
            complexity_factor: 1.0,
            priority: OperationPriority::Normal,
        };
        
        let verify_op = CryptoOperation {
            operation_type: OperationType::Verification,
            complexity_factor: 1.0,
            priority: OperationPriority::Normal,
        };
        
        // Should deny signing in emergency mode
        matches!(pm.should_allow_operation(sign_op), OperationDecision::Deny { .. });
        
        // Should allow verification in emergency mode
        matches!(pm.should_allow_operation(verify_op), OperationDecision::Allow);
    }
    
    #[test]
    fn test_energy_estimation() {
        let pm = PowerManager::new();
        
        let keygen_op = CryptoOperation {
            operation_type: OperationType::KeyGeneration,
            complexity_factor: 2.0,
            priority: OperationPriority::Normal,
        };
        
        let estimate = pm.estimate_energy_cost(keygen_op);
        
        // Key generation should be more expensive than verification
        assert!(estimate.energy_cost_mj > 10.0);
        assert!(estimate.estimated_time_ms > 0.0);
    }
}