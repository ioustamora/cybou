//! Cybou - Secure Cryptography Application
//!
//! A cross-platform GUI application for post-quantum cryptography operations
//! including encryption, digital signatures, key management, and cloud storage.

mod types;
// mod crypto; // Temporarily disabled during Slint migration
// mod ui; // Temporarily disabled during Slint migration
// mod backup; // Temporarily disabled - uses eframe
// mod cloud; // Temporarily disabled - uses eframe
mod windows;

use std::sync::{Arc, Mutex};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use tray_icon::menu::{Menu, MenuItem};

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

// Window manager for handling multiple Slint windows
struct WindowManager {
    app: types::App,
}

impl WindowManager {
    fn new() -> Self {
        Self {
            app: types::App::default(),
        }
    }

    fn show_main_dashboard(&mut self) {
        let window = MainDashboard::new().unwrap();
        self.setup_main_dashboard_callbacks(&window);
        window.show().unwrap();
        self.app.open_window(types::WindowType::MainDashboard);
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
                    // Handle window opening from main dashboard
                    match window_type.as_str() {
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

    fn setup_text_encryption_callbacks(&self, window: &TextEncryptionWindow) {
        let weak_window = window.as_weak();

        // Encrypt callback
        let weak_encrypt = weak_window.clone();
        window.on_encrypt(move || {
            let weak = weak_encrypt.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // TODO: Implement text encryption
                    window.set_status("Encrypting...".into());
                    println!("Encrypt clicked");
                }
            }).unwrap();
        });

        // Decrypt callback
        let weak_decrypt = weak_window.clone();
        window.on_decrypt(move || {
            let weak = weak_decrypt.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // TODO: Implement text decryption
                    window.set_status("Decrypting...".into());
                    println!("Decrypt clicked");
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
                    // TODO: Copy to clipboard
                    println!("Copy output clicked");
                }
            }).unwrap();
        });

        // Save output callback
        let weak_save = weak_window.clone();
        window.on_save_output(move || {
            let weak = weak_save.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // TODO: Save to file
                    println!("Save output clicked");
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
        // TODO: Implement password tools callbacks
        println!("Setting up password tools callbacks");
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
        wm.show_main_dashboard();
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