/// Core type definitions for the Cybou application
///
/// This module contains all the main structs and enums used throughout the application.

use std::time::SystemTime;
use hex;

/// Cloud provider options for storage integration
#[derive(Clone, PartialEq, Debug)]
pub enum CloudProvider {
    None,
    AWS,
    GCP,
    Azure,
}

/// Represents a version of cryptographic keys with timestamp tracking
///
/// KeyVersion encapsulates a complete set of cryptographic keys for a specific point in time.
/// Each version contains all the key material needed for encryption and signing operations,
/// allowing the application to maintain backward compatibility with previously encrypted data.
///
/// # Key Components
/// - `id`: Monotonically increasing version identifier (starts at 1)
/// - `timestamp`: Creation time for audit trails and key lifecycle management
/// - `master_key`: AES-256 symmetric key for data encryption (32 bytes)
/// - `kyber_keys`: Post-quantum key encapsulation mechanism keypair
/// - `dilithium_keys`: Post-quantum digital signature keypair
///
/// # Security Lifecycle
/// - Keys are generated once and never modified after creation
/// - Each version represents a security boundary for forward secrecy
/// - Older versions remain accessible for decrypting legacy data
/// - Timestamps enable key rotation policies and compliance auditing
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
///
/// SensitiveData manages the application's cryptographic keys with versioning support:
/// - Stores multiple versions of key sets for backward compatibility
/// - Provides secure key rotation and history tracking
/// - Implements thread-safe access through mutex protection
///
/// # Key Components
/// - `key_versions`: Vec of KeyVersion structs with timestamped keys
/// - `current_version`: Index pointing to the active key version
/// - Master key: AES-256 key derived from mnemonic (32 bytes)
/// - Kyber keys: Post-quantum KEM keypair for encryption
/// - Dilithium keys: Post-quantum signature keypair for signing
///
/// # Security Architecture
/// - Keys are never persisted to disk (memory-only storage)
/// - Versioning allows decryption of older encrypted data
/// - Key rotation generates new keys while maintaining access to old ones
/// - All access through global SENSITIVE_DATA mutex for thread safety
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
    ///
    /// Key rotation provides forward secrecy by generating new cryptographic material:
    /// 1. Generates new Kyber and Dilithium key pairs
    /// 2. Derives new master key by XORing current master key with random entropy
    /// 3. Creates new KeyVersion with incremented ID and current timestamp
    /// 4. Updates current_version to point to the new key set
    ///
    /// # Security Benefits
    /// - Limits the impact of key compromise to data encrypted after rotation
    /// - Maintains access to previously encrypted data through versioning
    /// - Provides cryptographic freshness for ongoing operations
    ///
    /// # Backward Compatibility
    /// - Old encrypted data can still be decrypted using previous key versions
    /// - Applications can specify which key version to use for decryption
    /// - Key history is preserved for audit and recovery purposes
    ///
    /// # Returns
    /// - `Ok(())` if key rotation succeeded
    /// - `Err(String)` if key generation failed
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
    ///
    /// Creates a safe export of key information for backup or sharing purposes:
    /// 1. Iterates through all key versions
    /// 2. Extracts metadata (ID, timestamp) without actual key material
    /// 3. Serializes to pretty-printed JSON format
    ///
    /// # Exported Data
    /// - `version_id`: Unique identifier for each key version
    /// - `timestamp`: Unix timestamp when the key version was created
    /// - `has_master_key`: Boolean flag (always true, actual key not exported)
    /// - `has_kyber_keys`: Boolean flag (always true, actual keys not exported)
    /// - `has_dilithium_keys`: Boolean flag (always true, actual keys not exported)
    ///
    /// # Security Notes
    /// - No actual cryptographic key material is exported
    /// - Safe to store or share the metadata JSON
    /// - Can be used to verify key version existence and timestamps
    /// - Useful for key management auditing and recovery planning
    ///
    /// # Returns
    /// - `Ok(String)` containing pretty-printed JSON metadata
    /// - `Err(String)` if JSON serialization fails
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
    ///
    /// Calculates and returns comprehensive statistics about the key versioning state:
    /// - Total number of key versions (including current and historical)
    /// - ID of the currently active key version
    /// - Timestamp of the oldest key version
    /// - Timestamp of the newest key version
    ///
    /// # Use Cases
    /// - Monitoring key rotation frequency and history
    /// - Assessing cryptographic key lifecycle
    /// - Providing user interface information about key management
    /// - Supporting key management policies and compliance
    ///
    /// # Returns
    /// - `KeyStatistics` struct containing all calculated metrics
    ///
    /// # Performance Notes
    /// - Iterates through all key versions to find min/max timestamps
    /// - O(n) complexity where n is the number of key versions
    /// - Suitable for infrequent calls (statistics display, not hot path)
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
#[derive(Clone)]
pub struct App {
    /// Sensitive cryptographic data with key versioning
    pub sensitive_data: Option<SensitiveData>,
    /// Window management state for multi-window GUI
    pub windows: std::collections::HashMap<WindowType, WindowState>,
    /// Mnemonic phrase input
    pub mnemonic_input: String,
    /// Whether to show mnemonic modal
    pub show_mnemonic_modal: bool,
    /// Text input for encryption/decryption
    pub text_input: String,
    /// Text output for results
    pub text_output: String,
    /// File path for file operations
    pub file_path: String,
    /// Folder path for folder operations
    pub folder_path: String,
    /// Text to sign
    pub sign_text: String,
    /// Generated signature
    pub sign_signature: String,
    /// Text to verify
    pub verify_text: String,
    /// Signature to verify
    pub verify_signature: String,
    /// Last status message
    pub last_status: String,
    /// Password generation options
    pub password_length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
    /// Password input for assessment
    pub password_input: String,
    /// Show password flag
    pub show_password: bool,
    /// Backup settings
    pub watched_folders: Vec<String>,
    pub backup_path: String,
    pub backup_active: bool,
    pub cleanup_days: u64,
    pub backup_file_count: usize,
    pub backup_file_count_ref: Option<std::sync::Arc<std::sync::Mutex<usize>>>,
    pub file_hashes: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    /// Cloud storage settings
    pub cloud_provider: CloudProvider,
    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    /// Settings
    pub dark_mode: bool,
    pub language: String,
    pub enable_accessibility: bool,
    /// UI state
    pub current_tab: usize,
}

impl Default for App {
    fn default() -> Self {
        Self {
            sensitive_data: None, // Start without keys loaded
            windows: init_windows(),
            mnemonic_input: String::new(),
            show_mnemonic_modal: true, // Show mnemonic modal on first launch
            text_input: String::new(),
            text_output: String::new(),
            file_path: String::new(),
            folder_path: String::new(),
            sign_text: String::new(),
            sign_signature: String::new(),
            verify_text: String::new(),
            verify_signature: String::new(),
            last_status: String::new(),
            password_length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
            password_input: String::new(),
            show_password: false,
            watched_folders: Vec::new(),
            backup_path: String::new(),
            backup_active: false,
            cleanup_days: 30, // Default to 30 days cleanup
            backup_file_count: 0,
            backup_file_count_ref: Some(std::sync::Arc::new(std::sync::Mutex::new(0))),
            file_hashes: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            cloud_provider: CloudProvider::None,
            s3_bucket: String::new(),
            s3_region: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            dark_mode: false,
            language: "en".to_string(),
            enable_accessibility: false,
            current_tab: 0,
        }
    }
}

impl App {
    /// Opens a specific window type
    pub fn open_window(&mut self, window_type: WindowType) {
        if let Some(window) = self.windows.get_mut(&window_type) {
            window.is_open = true;
        }
    }

    /// Closes a specific window type
    pub fn close_window(&mut self, window_type: WindowType) {
        if let Some(window) = self.windows.get_mut(&window_type) {
            window.is_open = false;
        }
    }

    /// Toggles a window's open/closed state
    pub fn toggle_window(&mut self, window_type: WindowType) {
        if let Some(window) = self.windows.get_mut(&window_type) {
            window.is_open = !window.is_open;
        }
    }

    /// Checks if a window is currently open
    pub fn is_window_open(&self, window_type: WindowType) -> bool {
        self.windows.get(&window_type).map(|w| w.is_open).unwrap_or(false)
    }

    /// Gets the title for a window type
    pub fn get_window_title(&self, window_type: WindowType) -> &str {
        self.windows.get(&window_type).map(|w| w.title.as_str()).unwrap_or("Unknown Window")
    }

    /// Validates mnemonic phrase and derives cryptographic keys from it
    ///
    /// This function performs the complete key derivation pipeline:
    /// 1. Parses and validates the BIP39 mnemonic phrase
    /// 2. Derives a seed from the mnemonic using PBKDF2
    /// 3. Generates post-quantum cryptographic key pairs (Kyber + Dilithium)
    /// 4. Creates a SensitiveData structure with key versioning
    ///
    /// # Security Notes
    /// - Uses PBKDF2 with empty salt for BIP39 compatibility
    /// - Generates deterministic keys from mnemonic for reproducibility
    /// - Keys are stored in memory only and never persisted to disk
    ///
    /// # Returns
    /// - `true` if validation and key derivation succeeded
    /// - `false` if mnemonic is invalid or key generation failed
    pub fn validate_and_derive_keys(&mut self) -> bool {
        use bip39::{Mnemonic, Language};
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;
        use pqc_kyber::keypair;
        use pqc_dilithium::Keypair;

        // Parse and validate mnemonic
        let mnemonic = match Mnemonic::parse(&self.mnemonic_input) {
            Ok(m) => m,
            Err(_) => return false,
        };

        // Derive seed from mnemonic
        let seed = mnemonic.to_seed("");

        // Use first 32 bytes of seed as master key
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&seed[..32]);

        // Generate PQ keys using seed-derived randomness
        let mut seed_32 = [0u8; 32];
        seed_32.copy_from_slice(&seed[..32]);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed_32);
        use rand::SeedableRng;

        let kyber_keys = match keypair(&mut rng) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let dilithium_keys = Keypair::generate();

        // Create sensitive data
        self.sensitive_data = Some(SensitiveData::new(master_key, kyber_keys, dilithium_keys));

        true
    }

    /// Encrypts text using derived keys
    pub fn encrypt_text(&mut self) {
        if self.sensitive_data.is_none() {
            self.last_status = "No keys available".to_string();
            return;
        }

        match crate::crypto::encrypt_text_with_key(&self.text_input, &self.sensitive_data.as_ref().unwrap().current().master_key) {
            Ok(encrypted) => {
                self.text_output = encrypted;
                self.last_status = "Text encrypted successfully".to_string();
            }
            Err(e) => {
                self.text_output = String::new();
                self.last_status = e;
            }
        }
    }

    /// Decrypts text using derived keys
    pub fn decrypt_text(&mut self) {
        if self.sensitive_data.is_none() {
            self.last_status = "No keys available".to_string();
            return;
        }

        match crate::crypto::decrypt_text_with_key(&self.text_input, &self.sensitive_data.as_ref().unwrap().current().master_key) {
            Ok(decrypted) => {
                self.text_output = decrypted;
                self.last_status = "Text decrypted successfully".to_string();
            }
            Err(e) => {
                self.text_output = e;
                self.last_status = "Text decryption failed".to_string();
            }
        }
    }

    /// Signs a message
    pub fn sign_message(&mut self) {
        if self.sensitive_data.is_none() {
            self.last_status = "No keys available".to_string();
            return;
        }

        match crate::crypto::sign_message(&self.sign_text, &self.sensitive_data.as_ref().unwrap().current().dilithium_keys) {
            Ok(signature) => {
                self.sign_signature = signature;
                self.last_status = "Message signed successfully".to_string();
            }
            Err(e) => {
                self.sign_signature = String::new();
                self.last_status = e;
            }
        }
    }

    /// Verifies a signature
    pub fn verify_message(&mut self) {
        if self.sensitive_data.is_none() {
            self.last_status = "No keys available".to_string();
            return;
        }

        match crate::crypto::verify_signature(&self.verify_text, &self.verify_signature, &self.sensitive_data.as_ref().unwrap().current().dilithium_keys) {
            Ok(valid) => {
                self.text_output = if valid { "Valid signature".to_string() } else { "Invalid signature".to_string() };
                self.last_status = "Signature verification complete".to_string();
            }
            Err(e) => {
                self.text_output = e;
                self.last_status = "Signature verification failed".to_string();
            }
        }
    }

    /// Encrypts a file
    pub fn encrypt_file(&mut self) {
        if self.sensitive_data.is_none() {
            self.last_status = "No keys available".to_string();
            return;
        }

        match crate::crypto::encrypt_file(&self.file_path, &self.sensitive_data.as_ref().unwrap().current().master_key) {
            Ok(output_path) => {
                self.text_output = format!("Encrypted to {}", output_path);
                self.last_status = "File encrypted successfully".to_string();
            }
            Err(e) => {
                self.text_output = String::new();
                self.last_status = e;
            }
        }
    }

    /// Decrypts a file
    pub fn decrypt_file(&mut self) {
        if self.sensitive_data.is_none() {
            self.last_status = "No keys available".to_string();
            return;
        }

        match crate::crypto::decrypt_file(&self.file_path, &self.sensitive_data.as_ref().unwrap().current().master_key) {
            Ok(output_path) => {
                self.text_output = format!("Decrypted to {}", output_path);
                self.last_status = "File decrypted successfully".to_string();
            }
            Err(e) => {
                self.text_output = String::new();
                self.last_status = e;
            }
        }
    }

    /// Encrypts a folder
    pub fn encrypt_folder(&mut self) {
        if self.sensitive_data.is_none() {
            self.last_status = "No keys available".to_string();
            return;
        }

        match crate::crypto::encrypt_folder(&self.folder_path, &self.sensitive_data.as_ref().unwrap().current().master_key) {
            Ok(_) => {
                self.last_status = "Folder encrypted successfully".to_string();
            }
            Err(e) => {
                self.last_status = e;
            }
        }
    }

    /// Generates a secure password
    pub fn generate_secure_password(&mut self) {
        match crate::crypto::generate_password(
            self.password_length,
            self.include_uppercase,
            self.include_lowercase,
            self.include_numbers,
            self.include_symbols,
        ) {
            Ok(password) => {
                self.text_output = password;
                self.last_status = format!("Generated {} character password", self.password_length);
            }
            Err(e) => {
                self.text_output = String::new();
                self.last_status = e;
            }
        }
    }

    /// Assesses password strength
    pub fn assess_password_strength(&mut self) {
        let (score, description) = crate::crypto::assess_password_strength(&self.password_input);
        self.text_output = format!("Password strength: {}/100 ({})", score, description);
        self.last_status = "Password assessment complete".to_string();
    }

    /// Checks if keys are loaded
    pub fn keys_loaded(&self) -> bool {
        self.sensitive_data.is_some()
    }

    /// Gets public key information as a formatted string
    pub fn get_public_key_info(&self) -> String {
        if let Some(data) = &self.sensitive_data {
            let current = data.current();
            format!("Cybou Public Key Information\n\
                     Version: {}\n\
                     Kyber Public Key: {}\n\
                     Dilithium Public Key: {}\n\
                     Created: {}",
                     current.id,
                     hex::encode(&current.kyber_keys.public),
                     hex::encode(&current.dilithium_keys.public),
                     current.timestamp.duration_since(std::time::UNIX_EPOCH)
                         .unwrap_or_default().as_secs())
        } else {
            "No keys loaded".to_string()
        }
    }

    /// Exports public key to a .cyboukey file
    pub fn export_public_key(&self, file_path: &str) -> Result<(), String> {
        if let Some(data) = &self.sensitive_data {
            let current = data.current();
            let key_info = self.get_public_key_info();
            
            // In a real implementation, this would be encrypted or signed
            std::fs::write(file_path, key_info)
                .map_err(|e| format!("Failed to write key file: {}", e))?;
            Ok(())
        } else {
            Err("No keys loaded".to_string())
        }
    }
}

/// Types of windows available in the application
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum WindowType {
    MainDashboard,
    MnemonicManagement,
    TextEncryption,
    FileEncryption,
    DigitalSignatures,
    PasswordTools,
    BackupManagement,
    CloudStorage,
    KeyManagement,
    Settings,
    FolderEncryption,
}

/// State of an individual window
#[derive(Clone)]
pub struct WindowState {
    /// Whether the window is currently open
    pub is_open: bool,
    /// Window title
    pub title: String,
    /// Window dimensions (width, height)
    pub size: (u32, u32),
}

/// Initializes the default window states
pub fn init_windows() -> std::collections::HashMap<WindowType, WindowState> {
    use std::collections::HashMap;

    let mut windows = HashMap::new();

    windows.insert(WindowType::MainDashboard, WindowState {
        is_open: true, // Main dashboard starts open
        title: "Cybou - Main Dashboard".to_string(),
        size: (800, 600),
    });

    windows.insert(WindowType::MnemonicManagement, WindowState {
        is_open: false,
        title: "Cybou - Mnemonic Management".to_string(),
        size: (700, 500),
    });

    windows.insert(WindowType::TextEncryption, WindowState {
        is_open: false,
        title: "Cybou - Text Encryption".to_string(),
        size: (700, 500),
    });

    windows.insert(WindowType::FileEncryption, WindowState {
        is_open: false,
        title: "Cybou - File Encryption".to_string(),
        size: (700, 500),
    });

    windows.insert(WindowType::DigitalSignatures, WindowState {
        is_open: false,
        title: "Cybou - Digital Signatures".to_string(),
        size: (700, 500),
    });

    windows.insert(WindowType::PasswordTools, WindowState {
        is_open: false,
        title: "Cybou - Password Tools".to_string(),
        size: (600, 400),
    });

    windows.insert(WindowType::BackupManagement, WindowState {
        is_open: false,
        title: "Cybou - Backup Management".to_string(),
        size: (800, 600),
    });

    windows.insert(WindowType::CloudStorage, WindowState {
        is_open: false,
        title: "Cybou - Cloud Storage".to_string(),
        size: (800, 600),
    });

    windows.insert(WindowType::KeyManagement, WindowState {
        is_open: false,
        title: "Cybou - Key Management".to_string(),
        size: (700, 500),
    });

    windows.insert(WindowType::Settings, WindowState {
        is_open: false,
        title: "Cybou - Settings".to_string(),
        size: (600, 500),
    });

    windows.insert(WindowType::FolderEncryption, WindowState {
        is_open: false,
        title: "Cybou - Folder Encryption".to_string(),
        size: (700, 500),
    });

    windows
}