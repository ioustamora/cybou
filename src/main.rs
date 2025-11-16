//! Cybou - Secure Cryptography Application
//!
//! A cross-platform GUI application for post-quantum cryptography operations
//! including encryption, digital signatures, key management, and cloud storage.

mod types;
mod crypto;
// mod ui; // Temporarily disabled during Slint migration
// mod backup; // Temporarily disabled - uses eframe
// mod cloud; // Temporarily disabled - uses eframe
mod windows;

use std::sync::{Arc, Mutex};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use tray_icon::menu::{Menu, MenuItem};
use slint::SharedString;
use clipboard::ClipboardProvider;

// Global sensitive data shared across windows
static SENSITIVE_DATA: Mutex<Option<types::SensitiveData>> = Mutex::new(None);

// Include the generated Slint UI modules
include!(concat!(env!("OUT_DIR"), "/main_dashboard.rs"));
include!(concat!(env!("OUT_DIR"), "/text_encryption.rs"));
include!(concat!(env!("OUT_DIR"), "/file_encryption.rs"));
include!(concat!(env!("OUT_DIR"), "/digital_signatures.rs"));
include!(concat!(env!("OUT_DIR"), "/password_tools.rs"));
include!(concat!(env!("OUT_DIR"), "/backup_management.rs"));
include!(concat!(env!("OUT_DIR"), "/cloud_storage.rs"));
include!(concat!(env!("OUT_DIR"), "/key_management.rs"));
include!(concat!(env!("OUT_DIR"), "/settings.rs"));
include!(concat!(env!("OUT_DIR"), "/folder_encryption.rs"));
include!(concat!(env!("OUT_DIR"), "/mnemonic_management.rs"));

// Window manager for handling multiple Slint windows
struct WindowManager {
    app: types::App,
    text_input: String,
    text_output: String,
    key_password: String,
    sensitive_data: Option<types::SensitiveData>,
}

impl WindowManager {
    fn new() -> Self {
        let sensitive_data = SENSITIVE_DATA.lock().unwrap().clone();
        Self {
            app: types::App::default(),
            text_input: String::new(),
            text_output: String::new(),
            key_password: String::new(),
            sensitive_data,
        }
    }

    fn encrypt_text_with_keys(&self, input_text: SharedString) -> (SharedString, SharedString) {
        if let Some(ref sensitive_data) = self.sensitive_data {
            match crate::crypto::encrypt_text_with_key(&input_text, &sensitive_data.current().master_key) {
                Ok(encrypted) => (encrypted.into(), "Text encrypted successfully".into()),
                Err(e) => ("".into(), e.into()),
            }
        } else {
            ("".into(), "No keys available - please load mnemonic first".into())
        }
    }

    fn decrypt_text_with_keys(&self, input_text: SharedString) -> (SharedString, SharedString) {
        if let Some(ref sensitive_data) = self.sensitive_data {
            match crate::crypto::decrypt_text_with_key(&input_text, &sensitive_data.current().master_key) {
                Ok(decrypted) => (decrypted.into(), "Text decrypted successfully".into()),
                Err(e) => ("".into(), e.into()),
            }
        } else {
            ("".into(), "No keys available - please load mnemonic first".into())
        }
    }

    fn generate_password(&self, length: i32, include_uppercase: bool, include_lowercase: bool, include_numbers: bool, include_symbols: bool) -> (SharedString, SharedString) {
        match crate::crypto::generate_password(length as usize, include_uppercase, include_lowercase, include_numbers, include_symbols) {
            Ok(password) => (password.into(), format!("Generated {} character password", length).into()),
            Err(e) => ("".into(), e.into()),
        }
    }

    fn assess_password_strength(&self, password: SharedString) -> (SharedString, SharedString) {
        let (score, description) = crate::crypto::assess_password_strength(&password);
        (format!("Password strength: {}/100 ({})", score, description).into(), "Password assessment complete".into())
    }

    fn copy_to_clipboard(&self, text: SharedString) -> SharedString {
        match clipboard::ClipboardContext::new() {
            Ok(mut ctx) => {
                match ctx.set_contents(text.to_string()) {
                    Ok(_) => "Copied to clipboard".into(),
                    Err(_) => "Failed to copy to clipboard".into(),
                }
            },
            Err(_) => "Clipboard not available".into(),
        }
    }

    fn save_to_file(&self, content: SharedString, filename: SharedString) -> SharedString {
        let path = if filename.is_empty() {
            match rfd::FileDialog::new()
                .set_title("Save encrypted text")
                .set_file_name("encrypted.txt")
                .save_file() {
                Some(p) => p,
                None => return "Save cancelled".into(),
            }
        } else {
            std::path::PathBuf::from(filename.as_str())
        };

        match std::fs::write(&path, content.as_bytes()) {
            Ok(_) => format!("Saved to {}", path.display()).into(),
            Err(e) => format!("Failed to save file: {}", e).into(),
        }
    }

    fn show_main_dashboard(&mut self) {
        let window = MainDashboard::new().unwrap();
        // Set keys loaded status
        let keys_loaded = SENSITIVE_DATA.lock().unwrap().is_some();
        window.set_keys_loaded(keys_loaded);
        self.setup_main_dashboard_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::MainDashboard);
    }

    fn show_mnemonic_management(&mut self) {
        let window = MnemonicManagement::new().unwrap();
        self.setup_mnemonic_management_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::MnemonicManagement);
    }

    fn show_text_encryption(&mut self) {
        let window = TextEncryptionWindow::new().unwrap();
        self.setup_text_encryption_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::TextEncryption);
    }

    fn show_file_encryption(&mut self) {
        let window = FileEncryptionWindow::new().unwrap();
        self.setup_file_encryption_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::FileEncryption);
    }

    fn show_digital_signatures(&mut self) {
        let window = DigitalSignaturesWindow::new().unwrap();
        self.setup_digital_signatures_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::DigitalSignatures);
    }

    fn show_password_tools(&mut self) {
        let window = PasswordToolsWindow::new().unwrap();
        self.setup_password_tools_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::PasswordTools);
    }

    fn show_backup_management(&mut self) {
        let window = BackupManagementWindow::new().unwrap();
        self.setup_backup_management_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::BackupManagement);
    }

    fn show_cloud_storage(&mut self) {
        let window = CloudStorageWindow::new().unwrap();
        self.setup_cloud_storage_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::CloudStorage);
    }

    fn show_key_management(&mut self) {
        let window = KeyManagementWindow::new().unwrap();
        self.setup_key_management_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::KeyManagement);
    }

    fn show_settings(&mut self) {
        let window = SettingsWindow::new().unwrap();
        self.setup_settings_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::Settings);
    }

    fn show_folder_encryption(&mut self) {
        let window = FolderEncryptionWindow::new().unwrap();
        self.setup_folder_encryption_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::FolderEncryption);
    }

    fn setup_main_dashboard_callbacks(&self, window: &MainDashboard) {
        let weak_window = window.as_weak();
        let app_clone = self.app.clone();
        window.on_open_window(move |window_type: slint::SharedString| {
            let app = app_clone.clone();
            let weak = weak_window.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Check if keys are loaded
                    let keys_loaded = SENSITIVE_DATA.lock().unwrap().is_some();
                    if !keys_loaded && window_type.as_str() != "mnemonic-management" {
                        // TODO: Show message that keys are required
                        return;
                    }
                    // Handle window opening from main dashboard
                    match window_type.as_str() {
                        "mnemonic-management" => {
                            let mut wm = WindowManager::new();
                            wm.show_mnemonic_management();
                        }
                        "text-encryption" => {
                            let mut wm = WindowManager::new();
                            wm.show_text_encryption();
                        }
                        "file-encryption" => {
                            let mut wm = WindowManager::new();
                            wm.show_file_encryption();
                        }
                        "digital-signatures" => {
                            let mut wm = WindowManager::new();
                            wm.show_digital_signatures();
                        }
                        "folder-encryption" => {
                            let mut wm = WindowManager::new();
                            wm.show_folder_encryption();
                        }
                        "password-tools" => {
                            let mut wm = WindowManager::new();
                            wm.show_password_tools();
                        }
                        "backup-management" => {
                            let mut wm = WindowManager::new();
                            wm.show_backup_management();
                        }
                        "cloud-storage" => {
                            let mut wm = WindowManager::new();
                            wm.show_cloud_storage();
                        }
                        "key-management" => {
                            let mut wm = WindowManager::new();
                            wm.show_key_management();
                        }
                        "settings" => {
                            let mut wm = WindowManager::new();
                            wm.show_settings();
                        }
                        _ => {}
                    }
                }
            }).unwrap();
        });

        window.on_clear_status(move || {
            // TODO: Clear status
            println!("Clear status clicked");
        });
    }

    fn setup_mnemonic_management_callbacks(&self, window: &MnemonicManagement) {
        let weak_window = window.as_weak();

        // Generate mnemonic callback
        let weak_generate = weak_window.clone();
        window.on_generate_mnemonic(move || {
            let weak = weak_generate.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    use bip39::{Mnemonic, Language};
                    let entropy: [u8; 16] = rand::random();
                    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
                    let mnemonic_str = mnemonic.to_string();
                    window.set_mnemonic_input(mnemonic_str.into());
                    window.set_status_text("New mnemonic generated".into());
                    window.set_is_valid(false);
                }
            }).unwrap();
        });

        // Validate mnemonic callback
        let weak_validate = weak_window.clone();
        window.on_validate_mnemonic(move || {
            let weak = weak_validate.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let mnemonic_input = window.get_mnemonic_input().to_string();
                    let is_valid = bip39::Mnemonic::parse(&mnemonic_input).is_ok();
                    window.set_is_valid(is_valid);
                    if is_valid {
                        window.set_status_text("Valid BIP39 mnemonic phrase ✓".into());
                    } else {
                        window.set_status_text("Invalid mnemonic phrase ✗".into());
                    }
                }
            }).unwrap();
        });

        // Continue with mnemonic callback
        let weak_continue = weak_window.clone();
        window.on_continue_with_mnemonic(move || {
            let weak = weak_continue.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let mnemonic_input = window.get_mnemonic_input().to_string();
                    // Create a temporary app instance to validate and derive keys
                    let mut temp_app = types::App::default();
                    temp_app.mnemonic_input = mnemonic_input;
                    if temp_app.validate_and_derive_keys() {
                        // Set the global sensitive data
                        *SENSITIVE_DATA.lock().unwrap() = temp_app.sensitive_data;
                        window.set_keys_loaded(true);
                        window.set_status_text("Keys loaded successfully ✓".into());
                    } else {
                        window.set_status_text("Failed to derive keys ✗".into());
                    }
                }
            }).unwrap();
        });

        // Copy mnemonic callback
        let weak_copy = weak_window.clone();
        window.on_copy_mnemonic(move || {
            let weak = weak_copy.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let mnemonic = window.get_mnemonic_input().to_string();
                    if mnemonic.is_empty() {
                        window.set_status_text("No mnemonic to copy".into());
                        return;
                    }
                    match clipboard::ClipboardContext::new() {
                        Ok(mut ctx) => {
                            match ctx.set_contents(mnemonic) {
                                Ok(_) => window.set_status_text("Mnemonic copied to clipboard".into()),
                                Err(_) => window.set_status_text("Failed to copy to clipboard".into()),
                            }
                        }
                        Err(_) => window.set_status_text("Clipboard not available".into()),
                    }
                }
            }).unwrap();
        });

        // Clear mnemonic callback
        let weak_clear = weak_window.clone();
        window.on_clear_mnemonic(move || {
            let weak = weak_clear.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    window.set_mnemonic_input("".into());
                    window.set_status_text("Mnemonic cleared".into());
                    window.set_is_valid(false);
                    window.set_keys_loaded(false);
                }
            }).unwrap();
        });
    }

    fn setup_text_encryption_callbacks(&self, window: &TextEncryptionWindow) {
        let weak_window = window.as_weak();

        // Encrypt callback
        let weak_encrypt = weak_window.clone();
        window.on_encrypt(move || {
            let weak = weak_encrypt.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Get input text
                    let input_text = window.get_input_text().to_string();
                    
                    // Create a temporary WindowManager for crypto operations
                    let wm = WindowManager::new();
                    let (output, status) = wm.encrypt_text_with_keys(input_text.into());
                    window.set_output_text(output);
                    window.set_status(status);
                }
            }).unwrap();
        });

        // Decrypt callback
        let weak_decrypt = weak_window.clone();
        window.on_decrypt(move || {
            let weak = weak_decrypt.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Get input text
                    let input_text = window.get_input_text().to_string();
                    
                    // Create a temporary WindowManager for crypto operations
                    let wm = WindowManager::new();
                    let (output, status) = wm.decrypt_text_with_keys(input_text.into());
                    window.set_output_text(output);
                    window.set_status(status);
                }
            }).unwrap();
        });

        // Clear callback
        let weak_clear = weak_window.clone();
        window.on_clear(move || {
            let weak = weak_clear.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    window.set_input_text("".into());
                    window.set_output_text("".into());
                    window.set_status("Ready".into());
                }
            }).unwrap();
        });

        // Copy output callback
        let weak_copy = weak_window.clone();
        window.on_copy_output(move || {
            let weak = weak_copy.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let output_text = window.get_output_text().to_string();
                    if output_text.is_empty() {
                        window.set_status("Error: No output text to copy".into());
                        return;
                    }
                    
                    match clipboard::ClipboardContext::new() {
                        Ok(mut ctx) => {
                            match ctx.set_contents(output_text.to_owned()) {
                                Ok(_) => window.set_status("Output copied to clipboard".into()),
                                Err(e) => window.set_status(format!("Error copying to clipboard: {}", e).into()),
                            }
                        }
                        Err(e) => window.set_status(format!("Error accessing clipboard: {}", e).into()),
                    }
                }
            }).unwrap();
        });

        // Save output callback
        let weak_save = weak_window.clone();
        window.on_save_output(move || {
            let weak = weak_save.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let output_text = window.get_output_text().to_string();
                    if output_text.is_empty() {
                        window.set_status("Error: No output text to save".into());
                        return;
                    }
                    
                    // Use rfd crate for file dialog
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Save Output")
                        .set_file_name("encrypted_output.txt")
                        .save_file() 
                    {
                        match std::fs::write(&path, &output_text) {
                            Ok(_) => window.set_status(format!("Output saved to: {}", path.display()).into()),
                            Err(e) => window.set_status(format!("Error saving file: {}", e).into()),
                        }
                    } else {
                        window.set_status("Save cancelled".into());
                    }
                }
            }).unwrap();
        });
    }

    fn setup_file_encryption_callbacks(&self, window: &FileEncryptionWindow) {
        // TODO: Implement file encryption callbacks
        println!("Setting up file encryption callbacks");
    }

    fn setup_digital_signatures_callbacks(&self, window: &DigitalSignaturesWindow) {
        // TODO: Implement digital signatures callbacks
        println!("Setting up digital signatures callbacks");
    }

    fn setup_password_tools_callbacks(&self, window: &PasswordToolsWindow) {
        let weak_window = window.as_weak();

        // Generate password callback
        let weak_generate = weak_window.clone();
        window.on_generate_password(move || {
            let weak = weak_generate.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Get password generation options
                    let length = window.get_password_length() as i32;
                    let include_uppercase = window.get_include_uppercase();
                    let include_lowercase = window.get_include_lowercase();
                    let include_numbers = window.get_include_numbers();
                    let include_symbols = window.get_include_symbols();

                    // Create a temporary WindowManager for password generation
                    let wm = WindowManager::new();
                    let (password, status) = wm.generate_password(length, include_uppercase, include_lowercase, include_numbers, include_symbols);
                    window.set_generated_password(password);
                    window.set_status(status);
                }
            }).unwrap();
        });

        // Check password strength callback
        let weak_check = weak_window.clone();
        window.on_check_strength(move || {
            let weak = weak_check.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Get password to check
                    let password = window.get_password_to_check().to_string();

                    // Create a temporary WindowManager for password assessment
                    let wm = WindowManager::new();
                    let (assessment, status) = wm.assess_password_strength(password.into());
                    window.set_password_assessment(assessment);
                    window.set_status(status);
                }
            }).unwrap();
        });

        // Copy password callback
        let weak_copy = weak_window.clone();
        window.on_copy_password(move || {
            let weak = weak_copy.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let password = window.get_generated_password().to_string();
                    if password.is_empty() {
                        window.set_status("No password to copy".into());
                        return;
                    }

                    // Create a temporary WindowManager for clipboard operations
                    let wm = WindowManager::new();
                    let status = wm.copy_to_clipboard(password.into());
                    window.set_status(status);
                }
            }).unwrap();
        });

        // Clear callback
        let weak_clear = weak_window.clone();
        window.on_clear(move || {
            let weak = weak_clear.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    window.set_generated_password("".into());
                    window.set_password_to_check("".into());
                    window.set_password_assessment("".into());
                    window.set_status("Ready".into());
                }
            }).unwrap();
        });
    }

    fn setup_backup_management_callbacks(&self, window: &BackupManagementWindow) {
        // TODO: Implement backup management callbacks
        println!("Setting up backup management callbacks");
    }

    fn setup_cloud_storage_callbacks(&self, window: &CloudStorageWindow) {
        // TODO: Implement cloud storage callbacks
        println!("Setting up cloud storage callbacks");
    }

    fn setup_key_management_callbacks(&self, window: &KeyManagementWindow) {
        // TODO: Implement key management callbacks
        println!("Setting up key management callbacks");
    }

    fn setup_settings_callbacks(&self, window: &SettingsWindow) {
        // TODO: Implement settings callbacks
        println!("Setting up settings callbacks");
    }

    fn setup_folder_encryption_callbacks(&self, window: &FolderEncryptionWindow) {
        // TODO: Implement folder encryption callbacks
        println!("Setting up folder encryption callbacks");
    }
}

/// Main application entry point
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the window manager
    let window_manager = Arc::new(Mutex::new(WindowManager::new()));

    // Initialize system tray icon
    let icon = Icon::from_rgba(vec![0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255, 0, 255, 0, 255], 2, 2).unwrap();
    let menu = Menu::new();
    let show_dashboard_item = MenuItem::new("Show Dashboard", true, None);
    let mnemonic_management_item = MenuItem::new("Mnemonic Management", true, None);
    let text_encryption_item = MenuItem::new("Text Encryption", true, None);
    let file_encryption_item = MenuItem::new("File Encryption", true, None);
    let digital_signatures_item = MenuItem::new("Digital Signatures", true, None);
    let password_tools_item = MenuItem::new("Password Tools", true, None);
    let backup_management_item = MenuItem::new("Backup Management", true, None);
    let cloud_storage_item = MenuItem::new("Cloud Storage", true, None);
    let key_management_item = MenuItem::new("Key Management", true, None);
    let settings_item = MenuItem::new("Settings", true, None);
    let quit_item = MenuItem::new("Quit", true, None);

    menu.append(&show_dashboard_item).unwrap();
    menu.append(&mnemonic_management_item).unwrap();
    menu.append(&text_encryption_item).unwrap();
    menu.append(&file_encryption_item).unwrap();
    menu.append(&digital_signatures_item).unwrap();
    menu.append(&password_tools_item).unwrap();
    menu.append(&backup_management_item).unwrap();
    menu.append(&cloud_storage_item).unwrap();
    menu.append(&key_management_item).unwrap();
    menu.append(&settings_item).unwrap();
    menu.append(&quit_item).unwrap();

    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .with_tooltip("Cybou - Secure Crypto App")
        .build()
        .unwrap();

    // Show the main dashboard on startup
    {
        let mut wm = window_manager.lock().unwrap();
        if wm.app.sensitive_data.is_none() {
            wm.show_mnemonic_management();
        } else {
            wm.show_main_dashboard();
        }
    }

    // Create a channel for tray events
    let (tx, rx) = std::sync::mpsc::channel();

    // Handle tray events in a separate thread
    std::thread::spawn(move || {
        TrayIconEvent::receiver().iter().for_each(|event| {
            match event {
                TrayIconEvent::Click { id, .. } => {
                    // Send the menu item ID to the main thread
                    let _ = tx.send(id);
                }
                _ => {}
            }
        });
    });

    // Handle tray menu clicks in the main thread
    let window_manager_clone = Arc::clone(&window_manager);
    std::thread::spawn(move || {
        while let Ok(menu_id) = rx.recv() {
            let wm = Arc::clone(&window_manager_clone);
            slint::invoke_from_event_loop(move || {
                let mut window_manager = wm.lock().unwrap();
                if menu_id == "Show Dashboard" {
                    window_manager.show_main_dashboard();
                } else if menu_id == "Mnemonic Management" {
                    window_manager.show_mnemonic_management();
                } else if menu_id == "Text Encryption" {
                    window_manager.show_text_encryption();
                } else if menu_id == "File Encryption" {
                    window_manager.show_file_encryption();
                } else if menu_id == "Digital Signatures" {
                    window_manager.show_digital_signatures();
                } else if menu_id == "Password Tools" {
                    window_manager.show_password_tools();
                } else if menu_id == "Backup Management" {
                    window_manager.show_backup_management();
                } else if menu_id == "Cloud Storage" {
                    window_manager.show_cloud_storage();
                } else if menu_id == "Key Management" {
                    window_manager.show_key_management();
                } else if menu_id == "Settings" {
                    window_manager.show_settings();
                } else if menu_id == "Quit" {
                    std::process::exit(0);
                }
            }).unwrap();
        }
    });

    // Run the Slint event loop
    slint::run_event_loop().unwrap();

    Ok(())
}