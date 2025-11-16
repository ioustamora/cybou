//! Cryptographic operations module
//!
//! This module contains all cryptographic functions including encryption,
//! decryption, signing, verification, and key management operations.

use rand::Rng;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use base64::{Engine as _, engine::general_purpose};

/// Size of the Kyber ciphertext in bytes
const CIPHERTEXT_SIZE: usize = 1088;

/// Encrypts text using AES-GCM with master key
pub fn encrypt_text_with_key(input: &str, master_key: &[u8; 32]) -> Result<String, String> {
    if input.is_empty() {
        return Err("Input text is empty".to_string());
    }

    let cipher = Aes256Gcm::new(master_key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, input.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    Ok(format!("{}:{}",
        general_purpose::STANDARD.encode(nonce_bytes),
        general_purpose::STANDARD.encode(&ciphertext)
    ))
}

/// Decrypts text using AES-GCM with master key
pub fn decrypt_text_with_key(input: &str, master_key: &[u8; 32]) -> Result<String, String> {
    if input.is_empty() {
        return Err("Input text is empty".to_string());
    }

    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid encrypted format".to_string());
    }

    let cipher = Aes256Gcm::new(master_key.into());

    let nonce_bytes = general_purpose::STANDARD.decode(parts[0])
        .map_err(|_| "Invalid base64 in nonce".to_string())?;
    let ciphertext = general_purpose::STANDARD.decode(parts[1])
        .map_err(|_| "Invalid base64 in ciphertext".to_string())?;

    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| "Decryption failed - wrong key or corrupted data".to_string())?;

    String::from_utf8(plaintext)
        .map_err(|_| "Invalid UTF-8 in decrypted data".to_string())
}

/// Signs a message using Dilithium keys
pub fn sign_message(message: &str, dilithium_keys: &pqc_dilithium::Keypair) -> Result<String, String> {
    if message.is_empty() {
        return Err("Message is empty".to_string());
    }

    let signature = dilithium_keys.sign(message.as_bytes());
    Ok(general_purpose::STANDARD.encode(signature))
}

/// Verifies a signature using Dilithium keys
pub fn verify_signature(message: &str, signature_b64: &str, dilithium_keys: &pqc_dilithium::Keypair) -> Result<bool, String> {
    if message.is_empty() {
        return Err("Message is empty".to_string());
    }

    let signature = general_purpose::STANDARD.decode(signature_b64)
        .map_err(|_| "Invalid base64 signature".to_string())?;

    // TODO: Fix dilithium verify API
    // Ok(dilithium_keys.verify(message.as_bytes(), &signature))
    Err("Signature verification not implemented yet".to_string())
}

/// Encrypts a file using master key
pub fn encrypt_file(file_path: &str, master_key: &[u8; 32]) -> Result<String, String> {
    use std::fs;
    use std::path::Path;

    if file_path.is_empty() {
        return Err("File path is empty".to_string());
    }

    let path = Path::new(file_path);
    if !path.exists() {
        return Err("File does not exist".to_string());
    }

    let data = fs::read(path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let encrypted = encrypt_text_with_key(&String::from_utf8_lossy(&data), master_key)?;

    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, encrypted)
        .map_err(|e| format!("Failed to write encrypted file: {}", e))?;

    Ok(output_path)
}

/// Decrypts a file using master key
pub fn decrypt_file(file_path: &str, master_key: &[u8; 32]) -> Result<String, String> {
    use std::fs;
    use std::path::Path;

    if file_path.is_empty() {
        return Err("File path is empty".to_string());
    }

    let path = Path::new(file_path);
    if !path.exists() {
        return Err("File does not exist".to_string());
    }

    let encrypted_data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read encrypted file: {}", e))?;

    let decrypted = decrypt_text_with_key(&encrypted_data, master_key)?;

    let output_path = file_path.trim_end_matches(".enc").to_string();
    fs::write(&output_path, decrypted)
        .map_err(|e| format!("Failed to write decrypted file: {}", e))?;

    Ok(output_path)
}

/// Encrypts a folder using master key
pub fn encrypt_folder(folder_path: &str, master_key: &[u8; 32]) -> Result<(), String> {
    use std::fs;
    use std::path::Path;

    if folder_path.is_empty() {
        return Err("Folder path is empty".to_string());
    }

    let path = Path::new(folder_path);
    if !path.exists() || !path.is_dir() {
        return Err("Folder does not exist".to_string());
    }

    // Create tar archive
    let tar_path = format!("{}.tar", folder_path);
    let tar_file = fs::File::create(&tar_path)
        .map_err(|e| format!("Failed to create tar file: {}", e))?;
    let mut tar = tar::Builder::new(tar_file);

    tar.append_dir_all(".", path)
        .map_err(|e| format!("Failed to create tar archive: {}", e))?;

    tar.finish()
        .map_err(|e| format!("Failed to finish tar archive: {}", e))?;

    // Encrypt the tar file
    encrypt_file(&tar_path, master_key)?;

    // Remove the tar file
    fs::remove_file(&tar_path)
        .map_err(|e| format!("Failed to remove temporary tar file: {}", e))?;

    Ok(())
}/// Generates a secure random password
pub fn generate_password(length: usize, include_uppercase: bool, include_lowercase: bool, include_numbers: bool, include_symbols: bool) -> Result<String, String> {
    if length == 0 {
        return Err("Password length must be greater than 0".to_string());
    }

    let mut charset = String::new();
    if include_lowercase { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
    if include_uppercase { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if include_numbers { charset.push_str("0123456789"); }
    if include_symbols { charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?"); }

    if charset.is_empty() {
        return Err("At least one character set must be selected".to_string());
    }

    let charset_bytes = charset.as_bytes();
    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset_bytes.len());
            charset_bytes[idx] as char
        })
        .collect();

    Ok(password)
}

/// Assesses password strength
pub fn assess_password_strength(password: &str) -> (i32, String) {
    if password.is_empty() {
        return (0, "Very Weak".to_string());
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
        _ => "Invalid",
    };

    (score, strength_description.to_string())
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