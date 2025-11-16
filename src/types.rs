/// Core type definitions for the Cybou application
///
/// This module contains all the main structs and enums used throughout the application.

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