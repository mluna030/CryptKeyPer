use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Serialize, Deserialize};
use zeroize::ZeroizeOnDrop;
#[cfg(feature = "parking_lot")]
use parking_lot::{RwLock, Mutex};
#[cfg(not(feature = "parking_lot"))]
use std::sync::{RwLock, Mutex};

use crate::errors::{CryptKeyperError, Result};

/// Encrypted XMSS state for persistent storage
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EncryptedXmssState {
    /// Encrypted private seed
    encrypted_private_seed: Vec<u8>,
    /// Encrypted signature index
    encrypted_signature_index: Vec<u8>,
    /// Maximum signatures allowed
    max_signatures: u64,
    /// Creation timestamp
    created_at: u64,
    /// Last updated timestamp
    updated_at: u64,
    /// Salt for key derivation
    salt: [u8; 32],
    /// Nonce for encryption
    nonce: [u8; 12],
    /// Version for compatibility
    version: u32,
}

/// Backup metadata
#[derive(Serialize, Deserialize, Clone)]
pub struct BackupInfo {
    /// Backup file path
    pub path: PathBuf,
    /// Signature index at backup time
    pub signature_index: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Backup integrity hash
    pub integrity_hash: Vec<u8>,
}

/// Secure state manager with atomic updates and backup support
pub struct SecureStateManager {
    /// Primary state file path
    state_file: PathBuf,
    /// Backup directory
    backup_dir: PathBuf,
    /// Maximum number of backups to keep
    max_backups: usize,
    /// Derived encryption key (stored in memory)
    encryption_key: Arc<RwLock<Option<[u8; 32]>>>,
    /// Current signature index (atomic for thread safety)
    current_index: AtomicU64,
    /// File lock for atomic operations
    file_lock: Arc<Mutex<()>>,
}

impl SecureStateManager {
    /// Create new secure state manager
    pub fn new<P: AsRef<Path>>(
        state_file: P,
        backup_dir: P,
        max_backups: usize,
    ) -> Result<Self> {
        let state_file = state_file.as_ref().to_path_buf();
        let backup_dir = backup_dir.as_ref().to_path_buf();
        
        // Create directories if they don't exist
        if let Some(parent) = state_file.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to create state directory: {}", e)))?;
        }
        
        std::fs::create_dir_all(&backup_dir)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to create backup directory: {}", e)))?;
        
        Ok(Self {
            state_file,
            backup_dir,
            max_backups,
            encryption_key: Arc::new(RwLock::new(None)),
            current_index: AtomicU64::new(0),
            file_lock: Arc::new(Mutex::new(())),
        })
    }
    
    /// Initialize with password-based key derivation
    pub fn initialize_with_password(&self, password: &str) -> Result<()> {
        if password.len() < 8 {
            return Err(CryptKeyperError::InvalidParameter(
                "Password must be at least 8 characters".to_string()
            ));
        }
        
        // Generate salt
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        
        // Derive key using scrypt
        let mut key = [0u8; 32];
        let params = ScryptParams::new(15, 8, 1, 32)
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("Scrypt params error: {}", e)))?;
        
        scrypt(password.as_bytes(), &salt, &params, &mut key)
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("Key derivation failed: {}", e)))?;
        
        // Store encryption key
        {
            #[cfg(feature = "parking_lot")]
            let mut encryption_key = self.encryption_key.write();
            #[cfg(not(feature = "parking_lot"))]
            let mut encryption_key = self.encryption_key.write().unwrap();
            *encryption_key = Some(key);
        }
        
        // Create initial state if file doesn't exist
        if !self.state_file.exists() {
            self.create_initial_state(salt)?;
        }
        
        Ok(())
    }
    
    /// Create initial encrypted state file
    fn create_initial_state(&self, salt: [u8; 32]) -> Result<()> {
        let initial_state = EncryptedXmssState {
            encrypted_private_seed: Vec::new(),
            encrypted_signature_index: Vec::new(),
            max_signatures: 0,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            salt,
            nonce: [0u8; 12],
            version: 1,
        };
        
        self.write_encrypted_state(&initial_state)?;
        Ok(())
    }
    
    /// Store XMSS state securely
    pub fn store_state(
        &self,
        private_seed: &[u8; 32],
        signature_index: u64,
        max_signatures: u64,
    ) -> Result<()> {
        let _lock = self.file_lock.lock();
        
        let encryption_key = {
            let key_guard = self.encryption_key.read();
            key_guard.ok_or_else(|| CryptKeyperError::InvalidParameter(
                "Encryption key not initialized".to_string()
            ))?
        };
        
        // Generate new nonce for this operation
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        
        // Encrypt private seed
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("AES key error: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted_private_seed = cipher
            .encrypt(nonce, private_seed.as_ref())
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("Encryption failed: {}", e)))?;
        
        // Encrypt signature index
        let encrypted_signature_index = cipher
            .encrypt(nonce, signature_index.to_le_bytes().as_ref())
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("Index encryption failed: {}", e)))?;
        
        // Read existing state to preserve salt
        let existing_state = self.read_encrypted_state().unwrap_or_else(|_| EncryptedXmssState {
            encrypted_private_seed: Vec::new(),
            encrypted_signature_index: Vec::new(),
            max_signatures: 0,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            updated_at: 0,
            salt: [0u8; 32],
            nonce: [0u8; 12],
            version: 1,
        });
        
        let state = EncryptedXmssState {
            encrypted_private_seed,
            encrypted_signature_index,
            max_signatures,
            created_at: existing_state.created_at,
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            salt: existing_state.salt,
            nonce: nonce_bytes,
            version: 1,
        };
        
        // Create backup before updating
        self.create_backup(signature_index)?;
        
        // Write new state atomically
        self.write_encrypted_state(&state)?;
        
        // Update in-memory index
        self.current_index.store(signature_index, Ordering::SeqCst);
        
        Ok(())
    }
    
    /// Load XMSS state securely
    pub fn load_state(&self) -> Result<([u8; 32], u64, u64)> {
        let _lock = self.file_lock.lock();
        
        let encryption_key = {
            let key_guard = self.encryption_key.read();
            key_guard.ok_or_else(|| CryptKeyperError::InvalidParameter(
                "Encryption key not initialized".to_string()
            ))?
        };
        
        let state = self.read_encrypted_state()?;
        
        // Decrypt private seed
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("AES key error: {}", e)))?;
        let nonce = aes_gcm::Nonce::from_slice(&state.nonce);
        
        let private_seed_bytes = cipher
            .decrypt(nonce, state.encrypted_private_seed.as_ref())
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("Decryption failed: {}", e)))?;
        
        if private_seed_bytes.len() != 32 {
            return Err(CryptKeyperError::KeyGenerationError(
                "Invalid private seed length".to_string()
            ));
        }
        
        let mut private_seed = [0u8; 32];
        private_seed.copy_from_slice(&private_seed_bytes);
        
        // Decrypt signature index
        let signature_index_bytes = cipher
            .decrypt(nonce, state.encrypted_signature_index.as_ref())
            .map_err(|e| CryptKeyperError::KeyGenerationError(format!("Index decryption failed: {}", e)))?;
        
        if signature_index_bytes.len() != 8 {
            return Err(CryptKeyperError::KeyGenerationError(
                "Invalid signature index length".to_string()
            ));
        }
        
        let signature_index = u64::from_le_bytes([
            signature_index_bytes[0], signature_index_bytes[1], signature_index_bytes[2], signature_index_bytes[3],
            signature_index_bytes[4], signature_index_bytes[5], signature_index_bytes[6], signature_index_bytes[7],
        ]);
        
        // Update in-memory index
        self.current_index.store(signature_index, Ordering::SeqCst);
        
        Ok((private_seed, signature_index, state.max_signatures))
    }
    
    /// Create a backup of the current state
    pub fn create_backup(&self, signature_index: u64) -> Result<BackupInfo> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let backup_filename = format!("xmss_state_backup_{}_{}.enc", signature_index, timestamp);
        let backup_path = self.backup_dir.join(backup_filename);
        
        // Copy current state file to backup
        std::fs::copy(&self.state_file, &backup_path)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Backup creation failed: {}", e)))?;
        
        // Calculate integrity hash
        let backup_data = std::fs::read(&backup_path)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Backup read failed: {}", e)))?;
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&backup_data);
        let integrity_hash = hasher.finalize().to_vec();
        
        let backup_info = BackupInfo {
            path: backup_path,
            signature_index,
            created_at: timestamp,
            integrity_hash,
        };
        
        // Clean up old backups
        self.cleanup_old_backups()?;
        
        Ok(backup_info)
    }
    
    /// Verify backup integrity
    pub fn verify_backup(&self, backup_info: &BackupInfo) -> Result<bool> {
        if !backup_info.path.exists() {
            return Ok(false);
        }
        
        let backup_data = std::fs::read(&backup_info.path)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Backup read failed: {}", e)))?;
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&backup_data);
        let computed_hash = hasher.finalize().to_vec();
        
        Ok(computed_hash == backup_info.integrity_hash)
    }
    
    /// List all available backups
    pub fn list_backups(&self) -> Result<Vec<BackupInfo>> {
        let mut backups = Vec::new();
        
        let entries = std::fs::read_dir(&self.backup_dir)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to read backup directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| CryptKeyperError::InvalidParameter(format!("Directory entry error: {}", e)))?;
            let path = entry.path();
            
            if path.is_file() && path.extension().is_some_and(|ext| ext == "enc") {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(backup_info) = self.parse_backup_filename(filename, path.clone()) {
                        backups.push(backup_info);
                    }
                }
            }
        }
        
        // Sort by creation time (newest first)
        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        
        Ok(backups)
    }
    
    /// Parse backup filename to extract metadata
    fn parse_backup_filename(&self, filename: &str, path: PathBuf) -> Option<BackupInfo> {
        // Expected format: xmss_state_backup_{index}_{timestamp}.enc
        let parts: Vec<&str> = filename.strip_suffix(".enc")?.split('_').collect();
        
        if parts.len() >= 4 && parts[0] == "xmss" && parts[1] == "state" && parts[2] == "backup" {
            let signature_index = parts[3].parse().ok()?;
            let created_at = parts[4].parse().ok()?;
            
            // Calculate integrity hash
            if let Ok(backup_data) = std::fs::read(&path) {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&backup_data);
                let integrity_hash = hasher.finalize().to_vec();
                
                return Some(BackupInfo {
                    path,
                    signature_index,
                    created_at,
                    integrity_hash,
                });
            }
        }
        
        None
    }
    
    /// Clean up old backups, keeping only the most recent ones
    fn cleanup_old_backups(&self) -> Result<()> {
        let backups = self.list_backups()?;
        
        if backups.len() > self.max_backups {
            let to_remove = &backups[self.max_backups..];
            
            for backup in to_remove {
                if let Err(e) = std::fs::remove_file(&backup.path) {
                    eprintln!("Warning: Failed to remove old backup {:?}: {}", backup.path, e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Read encrypted state from file
    fn read_encrypted_state(&self) -> Result<EncryptedXmssState> {
        let mut file = File::open(&self.state_file)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to open state file: {}", e)))?;
        
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to read state file: {}", e)))?;
        
        bincode::deserialize(&contents)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to deserialize state: {}", e)))
    }
    
    /// Write encrypted state to file atomically
    fn write_encrypted_state(&self, state: &EncryptedXmssState) -> Result<()> {
        let serialized = bincode::serialize(state)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to serialize state: {}", e)))?;
        
        // Write to temporary file first
        let temp_file = self.state_file.with_extension("tmp");
        
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_file)
                .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to create temp file: {}", e)))?;
            
            file.write_all(&serialized)
                .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to write temp file: {}", e)))?;
            
            file.sync_all()
                .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to sync temp file: {}", e)))?;
        }
        
        // Atomically replace the original file
        std::fs::rename(&temp_file, &self.state_file)
            .map_err(|e| CryptKeyperError::InvalidParameter(format!("Failed to replace state file: {}", e)))?;
        
        Ok(())
    }
    
    /// Get current signature index
    pub fn current_signature_index(&self) -> u64 {
        self.current_index.load(Ordering::SeqCst)
    }
}

use std::sync::Arc;
