//! Cryptographic operations module
//!
//! This module contains all cryptographic functions including encryption,
//! decryption, signing, verification, and key management operations.

use crate::types::{App, SensitiveData};
use base64::{Engine as _, engine::general_purpose};
use std::fs;
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;

/// Size of the Kyber ciphertext in bytes
const CIPHERTEXT_SIZE: usize = 1088;

impl App {
    /// Validates mnemonic phrase and derives cryptographic keys
    pub fn validate_and_derive_keys(&mut self) -> bool {
        use bip39::Mnemonic;
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;
        use pqc_kyber::keypair;
        use pqc_dilithium::Keypair;
        use rand::thread_rng;

        let mnemonic = match Mnemonic::parse(&self.mnemonic_input) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let seed = mnemonic.to_seed("");
        let mut master_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(&seed, b"cybou", 10000, &mut master_key);

        let rng = &mut thread_rng();
        let kyber_keys = keypair(rng).unwrap();
        let dilithium_keys = Keypair::generate();

        let dilithium_secret_slice = dilithium_keys.expose_secret();
        let mut dilithium_secret = [0u8; 4000];
        dilithium_secret.copy_from_slice(dilithium_secret_slice);

        self.sensitive_data = Some(SensitiveData::new(master_key, kyber_keys, dilithium_keys));
        true
    }

    /// Encrypts text using AES-GCM with the current master key
    pub fn encrypt_text(&mut self) {
        if let Some(data) = &self.sensitive_data {
            use aes_gcm::{Aes256Gcm, KeyInit};

            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&data.current().master_key);
            let cipher = Aes256Gcm::new(key);
            let nonce_bytes: [u8; 12] = rand::random();
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, self.text_input.as_bytes()).unwrap();
            self.text_output = general_purpose::STANDARD.encode(nonce_bytes) + ":" + &general_purpose::STANDARD.encode(&ciphertext);
            self.last_status = "Text encrypted successfully".to_string();
        } else {
            self.last_status = "No keys available".to_string();
        }
    }

    /// Decrypts text using AES-GCM with the current master key
    pub fn decrypt_text(&mut self) {
        if let Some(data) = &self.sensitive_data {
            let parts: Vec<&str> = self.text_input.split(':').collect();
            if parts.len() == 2 {
                if let (Ok(nonce_bytes), Ok(ciphertext)) = (general_purpose::STANDARD.decode(parts[0]), general_purpose::STANDARD.decode(parts[1])) {
                    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&data.current().master_key);
                    let cipher = Aes256Gcm::new(key);
                    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
                    if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext.as_slice()) {
                        self.text_output = String::from_utf8(plaintext).unwrap_or("Invalid UTF-8".to_string());
                        self.last_status = "Text decrypted successfully".to_string();
                    } else {
                        self.text_output = "Decryption failed".to_string();
                        self.last_status = "Decryption failed".to_string();
                    }
                } else {
                    self.text_output = "Invalid base64".to_string();
                    self.last_status = "Invalid base64 encoding".to_string();
                }
            } else {
                self.text_output = "Invalid format".to_string();
                self.last_status = "Invalid encrypted format".to_string();
            }
        } else {
            self.last_status = "No keys available".to_string();
        }
    }

    /// Encrypts a file using Kyber + AES-GCM hybrid encryption
    pub fn encrypt_file(&mut self) {
        if let Some(data) = &self.sensitive_data {
            use pqc_kyber::encapsulate;

            if let Ok(file_data) = fs::read(&self.file_path) {
                let (encapsulated_key, shared_secret) = encapsulate(&data.current().kyber_keys.public, &mut rand::thread_rng()).unwrap();
                let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_secret);
                let cipher = Aes256Gcm::new(key);
                let nonce_bytes: [u8; 12] = rand::random();
                let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
                let ciphertext = cipher.encrypt(nonce, file_data.as_slice()).unwrap();
                let mut output = Vec::new();
                output.extend_from_slice(&encapsulated_key);
                output.extend_from_slice(&nonce_bytes);
                output.extend_from_slice(&ciphertext);
                let output_path = self.file_path.clone() + ".enc";
                fs::write(&output_path, output).unwrap();
                self.text_output = format!("Encrypted to {}", output_path);
                self.last_status = "File encrypted successfully".to_string();
            } else {
                self.text_output = "Failed to read file".to_string();
                self.last_status = "Failed to read file".to_string();
            }
        } else {
            self.last_status = "No keys available".to_string();
        }
    }

    /// Decrypts a file using Kyber + AES-GCM hybrid decryption
    pub fn decrypt_file(&mut self) {
        if let Some(data) = &self.sensitive_data {
            use pqc_kyber::decapsulate;

            if let Ok(encrypted_data) = fs::read(&self.file_path) {
                if encrypted_data.len() > CIPHERTEXT_SIZE + 12 {
                    let encapsulated_key = &encrypted_data[0..CIPHERTEXT_SIZE];
                    let nonce_bytes = &encrypted_data[CIPHERTEXT_SIZE..CIPHERTEXT_SIZE + 12];
                    let ciphertext = &encrypted_data[CIPHERTEXT_SIZE + 12..];
                    let shared_secret = decapsulate(encapsulated_key, &data.current().kyber_keys.secret).unwrap();
                    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_secret);
                    let cipher = Aes256Gcm::new(key);
                    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
                    if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                        let output_path = self.file_path.trim_end_matches(".enc").to_string() + ".dec";
                        fs::write(&output_path, plaintext).unwrap();
                        self.text_output = format!("Decrypted to {}", output_path);
                        self.last_status = "File decrypted successfully".to_string();
                    } else {
                        self.text_output = "Decryption failed".to_string();
                        self.last_status = "Decryption failed".to_string();
                    }
                } else {
                    self.text_output = "Invalid encrypted file".to_string();
                    self.last_status = "Invalid encrypted file".to_string();
                }
            } else {
                self.text_output = "Failed to read file".to_string();
                self.last_status = "Failed to read file".to_string();
            }
        } else {
            self.last_status = "No keys available".to_string();
        }
    }

    /// Signs a message using Dilithium digital signatures
    pub fn sign_message(&mut self) {
        if let Some(data) = &self.sensitive_data {
            let sig = data.current().dilithium_keys.sign(self.sign_text.as_bytes());
            self.sign_signature = general_purpose::STANDARD.encode(sig);
            self.last_status = "Message signed successfully".to_string();
        } else {
            self.last_status = "No keys available".to_string();
        }
    }

    /// Verifies a digital signature using Dilithium
    pub fn verify_message(&mut self) {
        if let Some(data) = &self.sensitive_data {
            if let Ok(sig) = general_purpose::STANDARD.decode(&self.verify_signature) {
                let is_valid = pqc_dilithium::verify(&sig, self.verify_text.as_bytes(), &data.current().dilithium_keys.public).is_ok();
                self.text_output = if is_valid { "Valid signature" } else { "Invalid signature" }.to_string();
                self.last_status = self.text_output.clone();
            } else {
                self.text_output = "Invalid signature base64".to_string();
                self.last_status = "Invalid signature base64".to_string();
            }
        } else {
            self.last_status = "No keys available".to_string();
        }
    }

    /// Encrypts an entire folder by creating a compressed archive
    pub fn encrypt_folder(&mut self) {
        if let Some(_) = &self.sensitive_data {
            use tar::Builder;
            use flate2::Compression;
            use flate2::write::GzEncoder;

            let tar_path = format!("{}.tar.gz", self.folder_path);
            let tar_file = fs::File::create(&tar_path).unwrap();
            let enc = GzEncoder::new(tar_file, Compression::default());
            let mut tar = Builder::new(enc);
            let folder_name = std::path::Path::new(&self.folder_path).file_name().unwrap().to_str().unwrap();
            tar.append_dir_all(folder_name, &self.folder_path).unwrap();
            tar.finish().unwrap();
            self.file_path = tar_path;
            self.encrypt_file();
            self.last_status = "Folder encrypted successfully".to_string();
        } else {
            self.last_status = "No keys available".to_string();
        }
    }

    /// Generates a secure random password with specified length and character sets
    pub fn generate_secure_password(&mut self, length: usize, include_uppercase: bool, include_lowercase: bool, include_numbers: bool, include_symbols: bool) {
        use rand::Rng;

        if length == 0 {
            self.text_output = "Password length must be greater than 0".to_string();
            self.last_status = "Invalid password length".to_string();
            return;
        }

        let mut charset = String::new();
        if include_lowercase { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
        if include_uppercase { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
        if include_numbers { charset.push_str("0123456789"); }
        if include_symbols { charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?"); }

        if charset.is_empty() {
            self.text_output = "At least one character set must be selected".to_string();
            self.last_status = "No character sets selected".to_string();
            return;
        }

        let charset_bytes = charset.as_bytes();
        let mut rng = rand::thread_rng();
        let password: String = (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..charset_bytes.len());
                charset_bytes[idx] as char
            })
            .collect();

        self.text_output = password;
        self.last_status = format!("Generated {} character password", length);
    }

    /// Calculates the strength of a password on a scale of 0-100
    pub fn assess_password_strength(&mut self) {
        let password = &self.text_input;
        if password.is_empty() {
            self.text_output = "Password strength: 0/100 (Empty password)".to_string();
            self.last_status = "Password assessment complete".to_string();
            return;
        }

        let mut score: i32 = 0;
        let length = password.len();

        // Length scoring
        if length >= 8 { score += 25; }
        if length >= 12 { score += 15; }
        if length >= 16 { score += 10; }

        // Character variety scoring
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_digit(10));
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

        if has_lowercase { score += 10; }
        if has_uppercase { score += 10; }
        if has_digit { score += 10; }
        if has_symbol { score += 10; }

        // Bonus for all character types
        if has_lowercase && has_uppercase && has_digit && has_symbol {
            score += 20;
        }

        // Penalty for common patterns (very basic check)
        let common_patterns = ["123", "abc", "password", "qwerty", "admin"];
        for pattern in &common_patterns {
            if password.to_lowercase().contains(pattern) {
                score = score.saturating_sub(15);
            }
        }

        score = score.max(0).min(100);

        let strength_description = match score {
            0..=20 => "Very Weak",
            21..=40 => "Weak",
            41..=60 => "Fair",
            61..=80 => "Good",
            81..=100 => "Strong",
            _ => "Invalid", // This should never happen due to clamping
        };

        self.text_output = format!("Password strength: {}/100 ({})", score, strength_description);
        self.last_status = "Password assessment complete".to_string();
    }
}

#[cfg(test)]
mod tests {
    use crate::types::App;
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_and_derive_keys_valid_mnemonic() {
        let mut app = App::default();
        // Use a valid 12-word mnemonic for testing
        app.mnemonic_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let result = app.validate_and_derive_keys();
        assert!(result);
        assert!(app.sensitive_data.is_some());
    }

    #[test]
    fn test_validate_and_derive_keys_invalid_mnemonic() {
        let mut app = App::default();
        app.mnemonic_input = "invalid mnemonic phrase".to_string();

        let result = app.validate_and_derive_keys();
        assert!(!result);
        assert!(app.sensitive_data.is_none());
    }

    #[test]
    fn test_encrypt_decrypt_text_roundtrip() {
        let mut app = App::default();
        app.mnemonic_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        app.validate_and_derive_keys();

        let original_text = "Hello, World! This is a test message.";
        app.text_input = original_text.to_string();

        // Encrypt
        app.encrypt_text();
        assert_ne!(app.text_output, original_text);
        assert!(app.text_output.contains(":")); // Should contain nonce:ciphertext format

        // Decrypt
        app.text_input = app.text_output.clone();
        app.decrypt_text();
        assert_eq!(app.text_output, original_text);
    }

    #[test]
    fn test_encrypt_text_no_keys() {
        let mut app = App::default();
        app.text_input = "test message".to_string();

        app.encrypt_text();
        assert_eq!(app.last_status, "No keys available");
    }

    #[test]
    fn test_decrypt_text_no_keys() {
        let mut app = App::default();
        app.text_input = "invalid:encrypted:data".to_string();

        app.decrypt_text();
        assert_eq!(app.last_status, "No keys available");
    }

    #[test]
    fn test_decrypt_invalid_format() {
        let mut app = App::default();
        app.mnemonic_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        app.validate_and_derive_keys();

        app.text_input = "invalid_format_without_colon".to_string();
        app.decrypt_text();
        assert_eq!(app.text_output, "Invalid format");
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let mut app = App::default();
        app.mnemonic_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        app.validate_and_derive_keys();

        app.text_input = "invalid_base64:also_invalid".to_string();
        app.decrypt_text();
        assert_eq!(app.text_output, "Invalid base64");
    }

    #[test]
    fn test_sign_verify_message_roundtrip() {
        let mut app = App::default();
        app.mnemonic_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        app.validate_and_derive_keys();

        let message = "This message will be signed and verified.";
        app.sign_text = message.to_string();

        // Sign
        app.sign_message();
        assert!(!app.sign_signature.is_empty());
        assert!(app.sign_signature.len() > 100); // Base64 encoded signature should be long

        // Verify
        app.verify_text = message.to_string();
        app.verify_signature = app.sign_signature.clone();
        app.verify_message();
        assert_eq!(app.text_output, "Valid signature");
    }

    #[test]
    fn test_verify_invalid_signature() {
        let mut app = App::default();
        app.mnemonic_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        app.validate_and_derive_keys();

        app.verify_text = "test message".to_string();
        app.verify_signature = "invalid_signature".to_string();
        app.verify_message();
        assert_eq!(app.text_output, "Invalid signature base64");
    }

    #[test]
    fn test_sign_message_no_keys() {
        let mut app = App::default();
        app.sign_text = "test message".to_string();

        app.sign_message();
        assert_eq!(app.last_status, "No keys available");
    }

    #[test]
    fn test_verify_message_no_keys() {
        let mut app = App::default();
        app.verify_text = "test message".to_string();
        app.verify_signature = "dGVzdCBzaWduYXR1cmU=".to_string(); // base64 "test signature"

        app.verify_message();
        assert_eq!(app.last_status, "No keys available");
    }

    #[test]
    fn test_encrypt_file_no_keys() {
        let mut app = App::default();
        app.file_path = "/nonexistent/file.txt".to_string();

        app.encrypt_file();
        assert_eq!(app.last_status, "No keys available");
    }

    #[test]
    fn test_decrypt_file_no_keys() {
        let mut app = App::default();
        app.file_path = "/nonexistent/file.enc".to_string();

        app.decrypt_file();
        assert_eq!(app.last_status, "No keys available");
    }

    #[test]
    fn test_encrypt_folder_no_keys() {
        let mut app = App::default();
        app.folder_path = "/nonexistent/folder".to_string();

        app.encrypt_folder();
        assert_eq!(app.last_status, "No keys available");
    }

    #[test]
    fn test_encrypt_decrypt_file_roundtrip() {
        let mut app = App::default();
        app.mnemonic_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        app.validate_and_derive_keys();

        // Create a temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"Hello, World! This is test file content for encryption.";
        temp_file.write_all(test_content).unwrap();
        let temp_path = temp_file.path().to_str().unwrap().to_string();

        // Encrypt file
        app.file_path = temp_path.clone();
        app.encrypt_file();
        assert!(app.last_status.contains("File encrypted successfully"));
        assert!(app.text_output.contains(".enc"));

        // Decrypt file
        app.file_path = app.text_output.replace("Encrypted to ", "");
        app.decrypt_file();
        assert!(app.last_status.contains("File decrypted successfully"));

        // Verify content
        let decrypted_path = app.text_output.replace("Decrypted to ", "");
        let decrypted_content = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted_content, test_content);

        // Clean up
        let _ = fs::remove_file(app.file_path);
        let _ = fs::remove_file(decrypted_path);
    }
}