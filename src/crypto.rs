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
///
/// This function provides authenticated encryption using AES-256-GCM:
/// 1. Generates a random 96-bit nonce for each encryption operation
/// 2. Uses AES-256-GCM with the provided master key
/// 3. Returns base64-encoded nonce and ciphertext in format: "nonce:ciphertext"
///
/// # Arguments
/// * `input` - The plaintext text to encrypt (empty strings are rejected)
/// * `master_key` - 32-byte master key derived from mnemonic (must be exactly 32 bytes)
///
/// # Returns
/// * `Ok(String)` - Base64-encoded nonce and ciphertext separated by colon
/// * `Err(String)` - Error message if encryption fails or input is invalid
///
/// # Security Notes
/// - Each encryption uses a unique random nonce to prevent nonce reuse attacks
/// - AES-GCM provides both confidentiality and authenticity
/// - The output format is designed to be easily parsed for decryption
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
///
/// This function reverses the encryption process:
/// 1. Parses the input format "nonce:ciphertext" (base64 encoded)
/// 2. Decodes the nonce and ciphertext from base64
/// 3. Uses AES-256-GCM with the provided master key for decryption
/// 4. Verifies authenticity and returns the original plaintext
///
/// # Arguments
/// * `input` - Base64-encoded nonce and ciphertext in format "nonce:ciphertext"
/// * `master_key` - 32-byte master key that was used for encryption
///
/// # Returns
/// * `Ok(String)` - The decrypted plaintext as a UTF-8 string
/// * `Err(String)` - Error message for invalid format, base64 decoding failure,
///                  or authentication/decryption failure
///
/// # Security Notes
/// - AES-GCM authentication ensures ciphertext integrity
/// - Wrong key or corrupted data will result in authentication failure
/// - Invalid UTF-8 in decrypted data is treated as an error
pub fn decrypt_text_with_key(input: &str, master_key: &[u8; 32]) -> Result<String, String> {
    if input.is_empty() {
        return Err("Input text is empty".to_string());
    }

    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }

    let cipher = Aes256Gcm::new(master_key.into());

    let nonce_bytes = general_purpose::STANDARD.decode(parts[0])
        .map_err(|_| "Invalid base64".to_string())?;
    let ciphertext = general_purpose::STANDARD.decode(parts[1])
        .map_err(|_| "Invalid base64".to_string())?;

    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| "Decryption failed - wrong key or corrupted data".to_string())?;

    String::from_utf8(plaintext)
        .map_err(|_| "Invalid UTF-8 in decrypted data".to_string())
}

/// Signs a message using Dilithium keys
///
/// Creates a digital signature using the Dilithium post-quantum signature scheme:
/// 1. Validates that the message is not empty
/// 2. Signs the message bytes using the Dilithium private key
/// 3. Returns the signature as base64-encoded bytes
///
/// # Arguments
/// * `message` - The message to sign (empty messages are rejected)
/// * `dilithium_keys` - Dilithium keypair containing the private key for signing
///
/// # Returns
/// * `Ok(String)` - Base64-encoded signature bytes
/// * `Err(String)` - Error message if message is empty
///
/// # Security Notes
/// - Dilithium provides post-quantum security against signature forgery
/// - Signatures are deterministic for the same message and key
/// - The signature size is approximately 2KB for security level 2
pub fn sign_message(message: &str, dilithium_keys: &pqc_dilithium::Keypair) -> Result<String, String> {
    if message.is_empty() {
        return Err("Message is empty".to_string());
    }

    let signature = dilithium_keys.sign(message.as_bytes());
    Ok(general_purpose::STANDARD.encode(&signature))
}

/// Verifies a signature using Dilithium keys
///
/// Verifies a digital signature against a message using Dilithium:
/// 1. Validates that the message is not empty
/// 2. Decodes the signature from base64
/// 3. Verifies the signature using the Dilithium public key
/// 4. Returns whether the signature is valid
///
/// # Arguments
/// * `message` - The original message that was signed
/// * `signature_b64` - Base64-encoded signature to verify
/// * `dilithium_keys` - Dilithium keypair containing the public key for verification
///
/// # Returns
/// * `Ok(bool)` - `true` if signature is valid, `false` if invalid
/// * `Err(String)` - Error message for invalid message, base64 decoding failure,
///                  or signature format errors
///
/// # Security Notes
/// - Verification only requires the public key (private key not needed)
/// - Provides strong assurance that message was signed by private key holder
/// - Resistant to quantum computing attacks
pub fn verify_signature(message: &str, signature_b64: &str, dilithium_keys: &pqc_dilithium::Keypair) -> Result<bool, String> {
    if message.is_empty() {
        return Err("Message is empty".to_string());
    }

    let signature = general_purpose::STANDARD.decode(signature_b64)
        .map_err(|_| "Invalid signature base64".to_string())?;

    match pqc_dilithium::verify(&signature, message.as_bytes(), &dilithium_keys.public) {
        Ok(()) => Ok(true),
        Err(pqc_dilithium::SignError::Input) => Err("Invalid signature format".to_string()),
        Err(pqc_dilithium::SignError::Verify) => Ok(false),
    }
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

    let output_path = format!("{}.cybou", file_path);
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

    let output_path = file_path.trim_end_matches(".cybou").to_string() + "_decrypted";
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
///
/// Creates a cryptographically secure random password with customizable character sets:
/// 1. Validates that password length is greater than 0
/// 2. Builds a character set based on the selected options
/// 3. Generates random characters from the set using thread-local RNG
/// 4. Returns the password as a String
///
/// # Arguments
/// * `length` - Desired password length (must be > 0)
/// * `include_uppercase` - Include A-Z characters
/// * `include_lowercase` - Include a-z characters
/// * `include_numbers` - Include 0-9 digits
/// * `include_symbols` - Include special symbols (!@#$%^&*)
///
/// # Returns
/// * `Ok(String)` - The generated password
/// * `Err(String)` - Error if length is 0 or no character sets selected
///
/// # Security Notes
/// - Uses cryptographically secure random number generation
/// - Ensures at least one character set is selected to prevent weak passwords
/// - Each character is independently randomly selected
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
///
/// Evaluates password security using multiple criteria:
/// 1. Length scoring (8+ chars = 25pts, 12+ = 35pts, 16+ = 45pts)
/// 2. Character variety (10pts each for lowercase, uppercase, digits, symbols)
/// 3. Bonus for using all character types (20pts)
/// 4. Penalty for common patterns (-15pts each)
/// 5. Returns score (0-100) and descriptive strength level
///
/// # Arguments
/// * `password` - The password to assess
///
/// # Returns
/// * `(i32, String)` - Tuple of (score, description) where:
///   - score: 0-100 security score
///   - description: "Very Weak", "Weak", "Fair", "Good", "Strong", or "Invalid"
///
/// # Security Notes
/// - This is a basic heuristic assessment, not cryptanalysis
/// - Longer passwords with varied characters score higher
/// - Common patterns reduce the score significantly
/// - Empty passwords score 0
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
        assert!(app.text_output.contains(".cybou"));

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