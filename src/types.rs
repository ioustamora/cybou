//! Core type definitions for the Cybou application
//!
//! This module contains all the main structs and enums used throughout the application.

use std::time::SystemTime;

/// Cloud provider options for storage integration
#[derive(Clone, PartialEq, Debug)]
pub enum CloudProvider {
    None,
    AWS,
    GCP,
    Azure,
}

/// Represents a version of cryptographic keys with timestamp tracking
#[derive(Clone)]
pub struct KeyVersion {
    /// Unique identifier for this key version
    pub id: u64,
    /// Timestamp when this key version was created
    pub timestamp: SystemTime,
    /// Master encryption key (32 bytes)
    pub master_key: [u8; 32],
    /// Kyber post-quantum keypair for encryption
    pub kyber_keys: pqc_kyber::Keypair,
    /// Dilithium post-quantum keypair for signatures
    pub dilithium_keys: pqc_dilithium::Keypair,
}

/// Container for sensitive cryptographic data with version management
#[derive(Clone)]
pub struct SensitiveData {
    /// Index of the currently active key version
    pub current_version: usize,
    /// Vector of all key versions (for backward compatibility)
    pub key_versions: Vec<KeyVersion>,
}

impl SensitiveData {
    /// Creates a new SensitiveData instance with initial key version
    pub fn new(master_key: [u8; 32], kyber_keys: pqc_kyber::Keypair, dilithium_keys: pqc_dilithium::Keypair) -> Self {
        let key_version = KeyVersion {
            id: 1,
            timestamp: SystemTime::now(),
            master_key,
            kyber_keys,
            dilithium_keys,
        };

        Self {
            current_version: 0,
            key_versions: vec![key_version],
        }
    }

    /// Returns a reference to the currently active key version
    pub fn current(&self) -> &KeyVersion {
        &self.key_versions[self.current_version]
    }

    /// Rotates to a new set of cryptographic keys while preserving old versions
    pub fn rotate_keys(&mut self) -> Result<(), String> {
        use pqc_kyber::keypair;
        use pqc_dilithium::Keypair;
        use rand::thread_rng;

        // Generate new keys
        let rng = &mut thread_rng();
        let kyber_keys = keypair(rng).map_err(|e| format!("Failed to generate Kyber keys: {:?}", e))?;
        let dilithium_keys = Keypair::generate();

        // Generate new master key (derive from current master key with additional entropy)
        let mut new_master_key = [0u8; 32];
        let additional_entropy: [u8; 32] = rand::random();
        for i in 0..32 {
            new_master_key[i] = self.current().master_key[i] ^ additional_entropy[i];
        }

        let new_version = KeyVersion {
            id: self.key_versions.len() as u64 + 1,
            timestamp: SystemTime::now(),
            master_key: new_master_key,
            kyber_keys,
            dilithium_keys,
        };

        self.key_versions.push(new_version);
        self.current_version = self.key_versions.len() - 1;

        Ok(())
    }

    /// Retrieves a specific key version by ID
    pub fn get_version(&self, version_id: u64) -> Option<&KeyVersion> {
        self.key_versions.iter().find(|v| v.id == version_id)
    }

    /// Exports key metadata to JSON format (without sensitive key material)
    pub fn export_key_metadata(&self) -> Result<String, String> {
        use serde_json;

        #[derive(serde::Serialize)]
        struct KeyMetadata {
            version_id: u64,
            timestamp: u64,
            has_master_key: bool,
            has_kyber_keys: bool,
            has_dilithium_keys: bool,
        }

        let metadata: Vec<KeyMetadata> = self.key_versions.iter().map(|v| {
            KeyMetadata {
                version_id: v.id,
                timestamp: v.timestamp.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
                has_master_key: true, // We don't export the actual key
                has_kyber_keys: true,
                has_dilithium_keys: true,
            }
        }).collect();

        serde_json::to_string_pretty(&metadata)
            .map_err(|e| format!("Failed to serialize key metadata: {}", e))
    }

    /// Gets statistics about key versions
    pub fn get_key_statistics(&self) -> KeyStatistics {
        let total_versions = self.key_versions.len();
        let current_version_id = self.key_versions.get(self.current_version)
            .map(|v| v.id)
            .unwrap_or(0);

        let oldest_version = self.key_versions.iter()
            .min_by_key(|v| v.timestamp)
            .map(|v| v.timestamp);

        let newest_version = self.key_versions.iter()
            .max_by_key(|v| v.timestamp)
            .map(|v| v.timestamp);

        KeyStatistics {
            total_versions,
            current_version_id,
            oldest_version,
            newest_version,
        }
    }
}

/// Statistics about key versions
pub struct KeyStatistics {
    pub total_versions: usize,
    pub current_version_id: u64,
    pub oldest_version: Option<SystemTime>,
    pub newest_version: Option<SystemTime>,
}

/// Main application state structure
pub struct App {
    // Mnemonic and key management
    pub show_mnemonic_modal: bool,
    pub show_about_modal: bool,
    pub mnemonic_input: String,
    pub sensitive_data: Option<SensitiveData>,

    // UI state
    pub current_tab: usize,

    // Text encryption/decryption
    pub text_input: String,
    pub text_output: String,

    // Password tools
    pub password_length: usize,
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
    pub show_password: bool,
    pub password_input: String,

    // File operations
    pub file_path: String,

    // Digital signatures
    pub sign_text: String,
    pub sign_signature: String,
    pub verify_text: String,
    pub verify_signature: String,

    // Folder operations
    pub folder_path: String,

    // Backup system
    pub watched_folders: Vec<String>,
    pub backup_path: String,
    pub tray_icon: Option<tray_icon::TrayIcon>,
    pub last_status: String,
    pub backup_watcher: Option<notify::RecommendedWatcher>,
    pub file_hashes: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    pub backup_active: bool,
    pub backup_file_count: usize,
    pub backup_file_count_ref: Option<std::sync::Arc<std::sync::Mutex<usize>>>,

    // Cloud storage
    pub cloud_provider: CloudProvider,
    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_client: Option<aws_sdk_s3::Client>,

    // UI enhancement fields
    pub cleanup_days: u64,

    // User Experience features
    pub dark_mode: bool,
    pub language: String,
    pub enable_accessibility: bool,

    // Window management
    pub windows: std::collections::HashMap<crate::windows::WindowType, crate::windows::WindowState>,
}

impl Default for App {
    fn default() -> Self {
        let mut app = Self {
            show_mnemonic_modal: true,
            show_about_modal: false,
            mnemonic_input: String::new(),
            sensitive_data: None,
            current_tab: 0,
            text_input: String::new(),
            text_output: String::new(),
            password_length: 16,
            include_lowercase: true,
            include_uppercase: true,
            include_numbers: true,
            include_symbols: true,
            show_password: false,
            password_input: String::new(),
            file_path: String::new(),
            sign_text: String::new(),
            sign_signature: String::new(),
            verify_text: String::new(),
            verify_signature: String::new(),
            folder_path: String::new(),
            watched_folders: Vec::new(),
            backup_path: String::new(),
            tray_icon: None,
            last_status: String::new(),
            backup_watcher: None,
            file_hashes: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            backup_active: false,
            backup_file_count: 0,
            backup_file_count_ref: None,
            cloud_provider: CloudProvider::None,
            s3_bucket: String::new(),
            s3_region: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            s3_client: None,
            cleanup_days: 30,

            // User Experience features
            dark_mode: false,
            language: "en".to_string(),
            enable_accessibility: false,

            // Window management - will be initialized later
            windows: std::collections::HashMap::new(),
        };

        // Initialize windows
        app.init_windows();
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_sensitive_data_creation() {
        // Generate mock keys for testing
        let master_key = [42u8; 32];
        let rng = &mut rand::thread_rng();
        let kyber_keys = pqc_kyber::keypair(rng).unwrap();
        let dilithium_keys = pqc_dilithium::Keypair::generate();

        let data = SensitiveData::new(master_key, kyber_keys, dilithium_keys);

        assert_eq!(data.current_version, 0);
        assert_eq!(data.key_versions.len(), 1);
        assert_eq!(data.current().id, 1);
        assert_eq!(data.current().master_key, master_key);
    }

    #[test]
    fn test_key_rotation() {
        // Generate initial keys
        let master_key = [1u8; 32];
        let rng = &mut rand::thread_rng();
        let kyber_keys = pqc_kyber::keypair(rng).unwrap();
        let dilithium_keys = pqc_dilithium::Keypair::generate();

        let mut data = SensitiveData::new(master_key, kyber_keys, dilithium_keys);

        // Rotate keys
        data.rotate_keys().expect("Key rotation should succeed");

        assert_eq!(data.current_version, 1);
        assert_eq!(data.key_versions.len(), 2);
        assert_eq!(data.current().id, 2);
        assert_ne!(data.current().master_key, master_key); // New key should be different
    }

    #[test]
    fn test_get_version() {
        // Generate initial keys
        let master_key = [1u8; 32];
        let rng = &mut rand::thread_rng();
        let kyber_keys = pqc_kyber::keypair(rng).unwrap();
        let dilithium_keys = pqc_dilithium::Keypair::generate();

        let mut data = SensitiveData::new(master_key, kyber_keys, dilithium_keys);

        // Add another version
        data.rotate_keys().unwrap();

        // Test getting specific versions
        assert!(data.get_version(1).is_some());
        assert!(data.get_version(2).is_some());
        assert!(data.get_version(3).is_none()); // Non-existent version
    }

    #[test]
    fn test_key_version_timestamps() {
        let master_key = [1u8; 32];
        let rng = &mut rand::thread_rng();
        let kyber_keys = pqc_kyber::keypair(rng).unwrap();
        let dilithium_keys = pqc_dilithium::Keypair::generate();

        let data = SensitiveData::new(master_key, kyber_keys, dilithium_keys);

        // Check that timestamp is recent (within last minute)
        let now = SystemTime::now();
        let version_time = data.current().timestamp;
        let duration = now.duration_since(version_time).unwrap();
        assert!(duration.as_secs() < 60); // Should be less than a minute old
    }

    #[test]
    fn test_cloud_provider_enum() {
        let none = CloudProvider::None;
        let aws = CloudProvider::AWS;
        let gcp = CloudProvider::GCP;
        let azure = CloudProvider::Azure;

        assert_eq!(none, CloudProvider::None);
        assert_eq!(aws, CloudProvider::AWS);
        assert_eq!(gcp, CloudProvider::GCP);
        assert_eq!(azure, CloudProvider::Azure);
    }

    #[test]
    fn test_app_default_values() {
        let app = App::default();

        assert!(app.show_mnemonic_modal);
        assert!(app.mnemonic_input.is_empty());
        assert!(app.sensitive_data.is_none());
        assert_eq!(app.current_tab, 0);
        assert!(app.text_input.is_empty());
        assert!(app.text_output.is_empty());
        assert!(app.file_path.is_empty());
        assert!(app.sign_text.is_empty());
        assert!(app.sign_signature.is_empty());
        assert!(app.verify_text.is_empty());
        assert!(app.verify_signature.is_empty());
        assert!(app.folder_path.is_empty());
        assert!(app.watched_folders.is_empty());
        assert!(app.backup_path.is_empty());
        assert!(app.tray_icon.is_none());
        assert!(app.last_status.is_empty());
        assert!(app.backup_watcher.is_none());
        assert!(!app.backup_active);
        assert_eq!(app.backup_file_count, 0);
        assert!(app.backup_file_count_ref.is_none());
        assert_eq!(app.cloud_provider, CloudProvider::None);
        assert!(app.s3_bucket.is_empty());
        assert!(app.s3_region.is_empty());
        assert!(app.s3_access_key.is_empty());
        assert!(app.s3_secret_key.is_empty());
        assert!(app.s3_client.is_none());
    }
}