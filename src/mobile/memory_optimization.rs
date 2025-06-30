//! Memory optimization for mobile and embedded devices

use std::collections::HashMap;
use std::sync::{Arc, Weak, Mutex};
use std::time::Instant;
use crate::errors::Result;

/// Memory-efficient cache with mobile-specific optimizations
pub struct MobileMemoryCache<K, V> 
where 
    K: Clone + Eq + std::hash::Hash,
    V: Clone,
{
    cache: Arc<Mutex<HashMap<K, CacheEntry<V>>>>,
    max_size: usize,
    max_memory_bytes: usize,
    current_memory_bytes: usize,
    access_stats: AccessStatistics,
}

#[derive(Clone)]
struct CacheEntry<V> {
    value: V,
    last_accessed: Instant,
    access_count: u32,
    memory_size: usize,
}

#[derive(Debug, Default)]
struct AccessStatistics {
    hits: u64,
    misses: u64,
    evictions: u64,
    memory_pressure_events: u64,
}

impl<K, V> MobileMemoryCache<K, V>
where 
    K: Clone + Eq + std::hash::Hash,
    V: Clone,
{
    /// Create a new mobile-optimized cache
    pub fn new(max_size: usize, max_memory_mb: f64) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_size,
            max_memory_bytes: (max_memory_mb * 1024.0 * 1024.0) as usize,
            current_memory_bytes: 0,
            access_stats: AccessStatistics::default(),
        }
    }
    
    /// Insert with memory tracking
    pub fn insert(&mut self, key: K, value: V) -> Result<()> {
        let memory_size = self.estimate_memory_size(&value);
        
        // Check if we need to evict before inserting
        self.ensure_memory_capacity(memory_size)?;
        
        let entry = CacheEntry {
            value,
            last_accessed: Instant::now(),
            access_count: 1,
            memory_size,
        };
        
        let mut cache = self.cache.lock().unwrap();
        
        // Remove old entry if it exists
        if let Some(old_entry) = cache.remove(&key) {
            self.current_memory_bytes -= old_entry.memory_size;
        }
        
        cache.insert(key, entry);
        self.current_memory_bytes += memory_size;
        
        Ok(())
    }
    
    /// Get with access tracking
    pub fn get(&mut self, key: &K) -> Option<V> {
        let mut cache = self.cache.lock().unwrap();
        
        if let Some(entry) = cache.get_mut(key) {
            entry.last_accessed = Instant::now();
            entry.access_count += 1;
            self.access_stats.hits += 1;
            Some(entry.value.clone())
        } else {
            self.access_stats.misses += 1;
            None
        }
    }
    
    /// Ensure we have capacity for additional memory
    fn ensure_memory_capacity(&mut self, additional_bytes: usize) -> Result<()> {
        while self.current_memory_bytes + additional_bytes > self.max_memory_bytes {
            if !self.evict_one()? {
                // Could not evict anything
                return Err(crate::errors::CryptKeyperError::InsufficientMemory(
                    format!("Cannot fit {} bytes in cache", additional_bytes)
                ));
            }
        }
        Ok(())
    }
    
    /// Evict one entry using mobile-optimized strategy
    fn evict_one(&mut self) -> Result<bool> {
        let mut cache = self.cache.lock().unwrap();
        
        if cache.is_empty() {
            return Ok(false);
        }
        
        // Mobile-optimized eviction: prefer items that are large and rarely accessed
        let key_to_evict = cache
            .iter()
            .min_by(|a, b| {
                let score_a = self.calculate_eviction_score(&a.1);
                let score_b = self.calculate_eviction_score(&b.1);
                score_a.partial_cmp(&score_b).unwrap()
            })
            .map(|(k, _)| k.clone());
        
        if let Some(key) = key_to_evict {
            if let Some(entry) = cache.remove(&key) {
                self.current_memory_bytes -= entry.memory_size;
                self.access_stats.evictions += 1;
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Calculate eviction score (lower = more likely to evict)
    fn calculate_eviction_score<T>(&self, entry: &CacheEntry<T>) -> f64 {
        let age_seconds = entry.last_accessed.elapsed().as_secs() as f64;
        let access_frequency = entry.access_count as f64;
        let memory_pressure = entry.memory_size as f64 / 1024.0; // KB
        
        // Score favors recently accessed, frequently accessed, small items
        access_frequency * 10.0 - age_seconds * 0.1 - memory_pressure * 0.5
    }
    
    /// Handle memory pressure from system
    pub fn handle_memory_pressure(&mut self, pressure_level: MemoryPressureLevel) {
        self.access_stats.memory_pressure_events += 1;
        
        let target_reduction = match pressure_level {
            MemoryPressureLevel::Low => 0.1,    // Reduce by 10%
            MemoryPressureLevel::Medium => 0.3, // Reduce by 30%
            MemoryPressureLevel::High => 0.6,   // Reduce by 60%
            MemoryPressureLevel::Critical => 0.8, // Reduce by 80%
        };
        
        let target_memory = (self.current_memory_bytes as f64 * (1.0 - target_reduction)) as usize;
        
        while self.current_memory_bytes > target_memory {
            if !self.evict_one().unwrap_or(false) {
                break;
            }
        }
    }
    
    /// Get cache statistics
    pub fn statistics(&self) -> CacheStatistics {
        let cache = self.cache.lock().unwrap();
        
        CacheStatistics {
            size: cache.len(),
            max_size: self.max_size,
            memory_usage_bytes: self.current_memory_bytes,
            max_memory_bytes: self.max_memory_bytes,
            hit_rate: if self.access_stats.hits + self.access_stats.misses > 0 {
                self.access_stats.hits as f64 / (self.access_stats.hits + self.access_stats.misses) as f64
            } else {
                0.0
            },
            access_stats: self.access_stats.clone(),
        }
    }
    
    fn estimate_memory_size(&self, _value: &V) -> usize {
        // In a real implementation, this would calculate actual memory usage
        // For now, use a reasonable estimate
        std::mem::size_of::<V>() + 64 // Base overhead
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryPressureLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct CacheStatistics {
    pub size: usize,
    pub max_size: usize,
    pub memory_usage_bytes: usize,
    pub max_memory_bytes: usize,
    pub hit_rate: f64,
    pub access_stats: AccessStatistics,
}

/// Memory pool for efficient allocation on mobile devices
pub struct MobileMemoryPool {
    small_blocks: Vec<Vec<u8>>,  // 32-256 bytes
    medium_blocks: Vec<Vec<u8>>, // 256-4KB  
    large_blocks: Vec<Vec<u8>>,  // 4KB+
    total_allocated: usize,
    max_pool_size: usize,
}

impl MobileMemoryPool {
    pub fn new(max_pool_size_mb: f64) -> Self {
        Self {
            small_blocks: Vec::new(),
            medium_blocks: Vec::new(),
            large_blocks: Vec::new(),
            total_allocated: 0,
            max_pool_size: (max_pool_size_mb * 1024.0 * 1024.0) as usize,
        }
    }
    
    /// Allocate memory from pool or create new
    pub fn allocate(&mut self, size: usize) -> Vec<u8> {
        let pool = match size {
            s if s <= 256 => &mut self.small_blocks,
            s if s <= 4096 => &mut self.medium_blocks,
            _ => &mut self.large_blocks,
        };
        
        // Try to reuse existing allocation
        if let Some(mut block) = pool.pop() {
            if block.len() >= size {
                block.truncate(size);
                block.clear();
                block.resize(size, 0);
                return block;
            }
        }
        
        // Allocate new block
        let mut block = Vec::with_capacity(size);
        block.resize(size, 0);
        self.total_allocated += size;
        block
    }
    
    /// Return memory to pool for reuse
    pub fn deallocate(&mut self, block: Vec<u8>) {
        if self.total_allocated >= self.max_pool_size {
            // Pool is full, just drop the allocation
            return;
        }
        
        let size = block.capacity();
        let pool = match size {
            s if s <= 256 => &mut self.small_blocks,
            s if s <= 4096 => &mut self.medium_blocks,
            _ => &mut self.large_blocks,
        };
        
        // Limit pool size per category
        if pool.len() < 10 {
            pool.push(block);
        }
    }
    
    /// Clear pool to free memory
    pub fn clear(&mut self) {
        self.small_blocks.clear();
        self.medium_blocks.clear();
        self.large_blocks.clear();
        self.total_allocated = 0;
    }
    
    /// Get pool statistics
    pub fn statistics(&self) -> PoolStatistics {
        PoolStatistics {
            small_blocks_count: self.small_blocks.len(),
            medium_blocks_count: self.medium_blocks.len(),
            large_blocks_count: self.large_blocks.len(),
            total_allocated_bytes: self.total_allocated,
            max_pool_size_bytes: self.max_pool_size,
            utilization: self.total_allocated as f64 / self.max_pool_size as f64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStatistics {
    pub small_blocks_count: usize,
    pub medium_blocks_count: usize,
    pub large_blocks_count: usize,
    pub total_allocated_bytes: usize,
    pub max_pool_size_bytes: usize,
    pub utilization: f64,
}

/// Memory-efficient data structures for mobile cryptography
pub struct CompactBuffer {
    data: Vec<u8>,
    view_start: usize,
    view_len: usize,
}

impl CompactBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            view_start: 0,
            view_len: 0,
        }
    }
    
    /// Create a view into the buffer without copying
    pub fn view(&mut self, start: usize, len: usize) -> Option<&[u8]> {
        if start + len <= self.data.len() {
            self.view_start = start;
            self.view_len = len;
            Some(&self.data[start..start + len])
        } else {
            None
        }
    }
    
    /// Append data efficiently
    pub fn append(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }
    
    /// Compact the buffer by removing unused space
    pub fn compact(&mut self) {
        if self.view_start > 0 && self.view_len > 0 {
            // Move the viewed data to the beginning
            self.data.copy_within(self.view_start..self.view_start + self.view_len, 0);
            self.data.truncate(self.view_len);
            self.view_start = 0;
        }
    }
    
    /// Get current memory usage
    pub fn memory_usage(&self) -> usize {
        self.data.capacity()
    }
}

/// Mobile-optimized secure memory manager
pub struct SecureMemoryManager {
    secure_regions: Vec<SecureRegion>,
    total_secure_memory: usize,
    max_secure_memory: usize,
}

struct SecureRegion {
    data: Vec<u8>,
    in_use: bool,
    creation_time: Instant,
}

impl SecureMemoryManager {
    pub fn new(max_secure_mb: f64) -> Self {
        Self {
            secure_regions: Vec::new(),
            total_secure_memory: 0,
            max_secure_memory: (max_secure_mb * 1024.0 * 1024.0) as usize,
        }
    }
    
    /// Allocate secure memory that will be zeroized on drop
    pub fn allocate_secure(&mut self, size: usize) -> Result<SecureMemoryHandle> {
        if self.total_secure_memory + size > self.max_secure_memory {
            return Err(crate::errors::CryptKeyperError::InsufficientMemory(
                "Secure memory limit exceeded".to_string()
            ));
        }
        
        let mut data = vec![0u8; size];
        
        // Use mlock if available to prevent swapping
        #[cfg(unix)]
        {
            unsafe {
                let ptr = data.as_mut_ptr();
                libc::mlock(ptr as *const libc::c_void, size);
            }
        }
        
        let region_id = self.secure_regions.len();
        self.secure_regions.push(SecureRegion {
            data,
            in_use: true,
            creation_time: Instant::now(),
        });
        
        self.total_secure_memory += size;
        
        Ok(SecureMemoryHandle {
            region_id,
            manager: self as *mut Self,
        })
    }
    
    /// Get mutable access to secure memory
    fn get_secure_mut(&mut self, region_id: usize) -> Option<&mut [u8]> {
        self.secure_regions.get_mut(region_id)
            .filter(|r| r.in_use)
            .map(|r| r.data.as_mut_slice())
    }
    
    /// Deallocate secure memory with explicit zeroization
    fn deallocate_secure(&mut self, region_id: usize) {
        if let Some(region) = self.secure_regions.get_mut(region_id) {
            if region.in_use {
                // Explicitly zero the memory
                for byte in region.data.iter_mut() {
                    *byte = 0;
                }
                
                #[cfg(unix)]
                {
                    unsafe {
                        let ptr = region.data.as_ptr();
                        libc::munlock(ptr as *const libc::c_void, region.data.len());
                    }
                }
                
                self.total_secure_memory -= region.data.len();
                region.in_use = false;
            }
        }
    }
}

/// Handle for secure memory that zeroizes on drop
pub struct SecureMemoryHandle {
    region_id: usize,
    manager: *mut SecureMemoryManager,
}

impl SecureMemoryHandle {
    /// Get mutable access to the secure memory
    pub fn as_mut_slice(&mut self) -> Option<&mut [u8]> {
        unsafe {
            (*self.manager).get_secure_mut(self.region_id)
        }
    }
}

impl Drop for SecureMemoryHandle {
    fn drop(&mut self) {
        unsafe {
            (*self.manager).deallocate_secure(self.region_id);
        }
    }
}

// Safety: SecureMemoryHandle is only safe to send if the manager outlives it
unsafe impl Send for SecureMemoryHandle {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mobile_cache() {
        let mut cache: MobileMemoryCache<String, Vec<u8>> = MobileMemoryCache::new(10, 1.0);
        
        // Insert some data
        cache.insert("key1".to_string(), vec![1, 2, 3]).unwrap();
        cache.insert("key2".to_string(), vec![4, 5, 6]).unwrap();
        
        // Retrieve data
        assert_eq!(cache.get(&"key1".to_string()), Some(vec![1, 2, 3]));
        assert_eq!(cache.get(&"nonexistent".to_string()), None);
        
        let stats = cache.statistics();
        assert!(stats.hit_rate > 0.0);
    }
    
    #[test]
    fn test_memory_pool() {
        let mut pool = MobileMemoryPool::new(1.0);
        
        // Allocate and deallocate
        let block1 = pool.allocate(128);
        let block2 = pool.allocate(1024);
        
        assert_eq!(block1.len(), 128);
        assert_eq!(block2.len(), 1024);
        
        pool.deallocate(block1);
        pool.deallocate(block2);
        
        let stats = pool.statistics();
        assert!(stats.small_blocks_count > 0 || stats.medium_blocks_count > 0);
    }
    
    #[test]
    fn test_compact_buffer() {
        let mut buffer = CompactBuffer::new(1024);
        
        buffer.append(&[1, 2, 3, 4]);
        buffer.append(&[5, 6, 7, 8]);
        
        let view = buffer.view(2, 4);
        assert_eq!(view, Some([3, 4, 5, 6].as_slice()));
        
        buffer.compact();
        assert!(buffer.memory_usage() <= 1024);
    }
}