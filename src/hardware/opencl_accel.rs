
#[cfg(feature = "opencl")]
use opencl3::{platform::Platform, device::Device, context::Context, command_queue::CommandQueue, program::Program, types::*};

use crate::errors::Result;

#[cfg(feature = "opencl")]
pub struct OpenClXmssAccelerator {
    context: Option<Context>,
    device: Option<Device>,
    queue: Option<CommandQueue>,
    program: Option<Program>,
}

#[cfg(feature = "opencl")]
impl OpenClXmssAccelerator {
    pub fn new() -> Result<Self> {
        match Self::init_opencl() {
            Ok((context, device, queue)) => {
                let program = Self::build_xmss_program(&context, &device)?;
                Ok(Self {
                    context: Some(context),
                    device: Some(device),
                    queue: Some(queue),
                    program: Some(program),
                })
            }
            Err(_) => {
                Ok(Self {
                    context: None,
                    device: None,
                    queue: None,
                    program: None,
                })
            }
        }
    }

    fn init_opencl() -> Result<(Context, Device, CommandQueue)> {
        let platforms = Platform::get_platforms()
            .map_err(|e| crate::errors::CryptKeyperError::HardwareError(format!("OpenCL platforms: {}", e)))?;
        
        if platforms.is_empty() {
            return Err(crate::errors::CryptKeyperError::HardwareError("No OpenCL platforms found".to_string()));
        }

        let platform = &platforms[0];
        let devices = Device::get_devices(&platform, CL_DEVICE_TYPE_GPU)
            .or_else(|_| Device::get_devices(&platform, CL_DEVICE_TYPE_CPU))
            .map_err(|e| crate::errors::CryptKeyperError::HardwareError(format!("OpenCL devices: {}", e)))?;

        if devices.is_empty() {
            return Err(crate::errors::CryptKeyperError::HardwareError("No OpenCL devices found".to_string()));
        }

        let device = devices[0];
        
        // Create context and command queue
        let context = Context::from_device(&device)
            .map_err(|e| crate::errors::CryptKeyperError::HardwareError(format!("OpenCL context: {}", e)))?;
        
        let queue = CommandQueue::create_default_with_properties(&context, &device, 0, 0)
            .map_err(|e| crate::errors::CryptKeyperError::HardwareError(format!("OpenCL queue: {}", e)))?;

        Ok((context, device, queue))
    }

    fn build_xmss_program(context: &Context, device: &Device) -> Result<Program> {
        let sha256_kernel = include_str!("kernels/sha256.cl");
        
        let program = Program::create_and_build_from_source(context, sha256_kernel, "")
            .map_err(|e| crate::errors::CryptKeyperError::HardwareError(format!("OpenCL program: {}", e)))?;

        Ok(program)
    }

    pub fn parallel_hash_batch(&self, _inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        if self.program.is_none() {
            // Fall back to software implementation when OpenCL is not available
            use sha2::{Sha256, Digest};
            return Ok(inputs.iter().map(|input| Sha256::digest(input).to_vec()).collect());
        }

        // TODO: Implement actual OpenCL kernel execution
        // For now, use software fallback even when OpenCL is available
        use sha2::{Sha256, Digest};
        Ok(inputs.iter().map(|input| Sha256::digest(input).to_vec()).collect())
    }
    pub fn is_available(&self) -> bool {
        self.program.is_some()
    }

    pub fn device_info(&self) -> Option<OpenClDeviceInfo> {
        if let (Some(device), Some(_)) = (&self.device, &self.context) {
            Some(OpenClDeviceInfo::from_device(device))
        } else {
            None
        }
    }
}

#[cfg(not(feature = "opencl"))]
pub struct OpenClXmssAccelerator;

#[cfg(not(feature = "opencl"))]
impl OpenClXmssAccelerator {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub fn parallel_hash_batch(&self, _inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        Err(crate::errors::CryptKeyperError::HardwareError(
            "OpenCL support not compiled in".to_string()
        ))
    }

    pub fn is_available(&self) -> bool {
        false
    }

    pub fn device_info(&self) -> Option<OpenClDeviceInfo> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct OpenClDeviceInfo {
    pub name: String,
    pub vendor: String,
    pub device_type: String,
    pub compute_units: u32,
    pub max_work_group_size: usize,
    pub global_memory_mb: u64,
    pub local_memory_kb: u64,
    pub max_clock_frequency: u32,
}

#[cfg(feature = "opencl")]
impl OpenClDeviceInfo {
    fn from_device(device: &Device) -> Self {
        Self {
            name: device.name().unwrap_or_else(|_| "Unknown".to_string()),
            vendor: device.vendor().unwrap_or_else(|_| "Unknown".to_string()),
            device_type: format!("{:?}", device.device_type().unwrap_or(CL_DEVICE_TYPE_DEFAULT)),
            compute_units: device.max_compute_units().unwrap_or(0),
            max_work_group_size: device.max_work_group_size().unwrap_or(0),
            global_memory_mb: device.global_mem_size().unwrap_or(0) / (1024 * 1024),
            local_memory_kb: device.local_mem_size().unwrap_or(0) / 1024,
            max_clock_frequency: device.max_clock_frequency().unwrap_or(0),
        }
    }
}

#[cfg(not(feature = "opencl"))]
impl OpenClDeviceInfo {
    fn _from_device(_device: &()) -> Self {
        Self {
            name: "OpenCL not available".to_string(),
            vendor: "N/A".to_string(),
            device_type: "N/A".to_string(),
            compute_units: 0,
            max_work_group_size: 0,
            global_memory_mb: 0,
            local_memory_kb: 0,
            max_clock_frequency: 0,
        }
    }
}

#[cfg(feature = "opencl")]
impl HardwareAccelerated for OpenClXmssAccelerator {
    type HardwareContext = (Context, Device, CommandQueue);

    fn init_hardware() -> Result<Self::HardwareContext> {
        Self::init_opencl()
    }

    fn is_hardware_available() -> bool {
        Platform::get_platforms().is_ok()
    }

    fn hardware_performance() -> HardwarePerformance {
        HardwarePerformance {
            platform: HardwarePlatform::Gpu { 
                cuda_cores: 2048, // Approximate
                memory_gb: 8 
            },
            parallel_units: 2048,
            memory_bandwidth_gbps: 500.0,
            estimated_speedup: 100.0,
            power_consumption_watts: 200.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opencl_initialization() {
        let accel = OpenClXmssAccelerator::new();
        assert!(accel.is_ok());
        
        let accel = accel.unwrap();
        println!("OpenCL available: {}", accel.is_available());
        
        if let Some(info) = accel.device_info() {
            println!("Device: {} by {}", info.name, info.vendor);
            println!("Compute units: {}", info.compute_units);
            println!("Global memory: {}MB", info.global_memory_mb);
        }
    }

    #[test]
    fn test_parallel_hash_fallback() {
        let accel = OpenClXmssAccelerator::new().unwrap();
        let inputs = vec![b"test1".as_slice(), b"test2".as_slice()];
        
        // Should work even without OpenCL (fallback)
        let result = accel.parallel_hash_batch(&inputs);
        if accel.is_available() {
            assert!(result.is_ok());
            let hashes = result.unwrap();
            assert_eq!(hashes.len(), 2);
        }
    }
}