//! Window management module
//!
//! This module handles the multi-window GUI architecture, allowing different
//! application features to be displayed in separate windows. It provides
//! centralized window creation, management, and coordination functionality.

use crate::types::{App, WindowType};
use clipboard::ClipboardProvider;
use slint::ComponentHandle;

/// Window management system for coordinating multi-window GUI operations
///
/// This struct provides centralized management of all application windows,
/// handling their lifecycle, state coordination, and inter-window communication.
/// It maintains references to active windows and provides methods for opening,
/// closing, and managing window states.
pub struct WindowCoordinator {
    /// Reference to the main application state
    app: std::sync::Arc<std::sync::Mutex<App>>,
}

impl WindowCoordinator {
    /// Creates a new window coordinator with the given application state
    ///
    /// # Arguments
    /// * `app` - Shared reference to the main application state
    ///
    /// # Returns
    /// * `WindowCoordinator` - New coordinator instance
    pub fn new(app: std::sync::Arc<std::sync::Mutex<App>>) -> Self {
        Self { app }
    }

    /// Opens a window of the specified type
    ///
    /// Creates and displays a new window instance, updating the application
    /// state and tracking the window reference for lifecycle management.
    ///
    /// # Arguments
    /// * `window_type` - The type of window to open
    ///
    /// # Returns
    /// * `Result<(), String>` - Success or error message
    pub fn open_window(&mut self, window_type: WindowType) -> Result<(), String> {
        // Check if window is already open
        if self.is_window_open(window_type) {
            return Err(format!("Window {:?} is already open", window_type));
        }

        // Update application state
        {
            let mut app = self.app.lock().map_err(|e| format!("Failed to lock app state: {}", e))?;
            app.open_window(window_type);
        }

        // Create and show the window
        match window_type {
            WindowType::MainDashboard => self.show_main_dashboard(),
            WindowType::MnemonicManagement => self.show_mnemonic_management(),
            WindowType::TextEncryption => self.show_text_encryption(),
            WindowType::FileEncryption => self.show_file_encryption(),
            WindowType::DigitalSignatures => self.show_digital_signatures(),
            WindowType::PasswordTools => self.show_password_tools(),
            WindowType::BackupManagement => self.show_backup_management(),
            WindowType::CloudStorage => self.show_cloud_storage(),
            WindowType::KeyManagement => self.show_key_management(),
            WindowType::Settings => self.show_settings(),
            WindowType::FolderEncryption => self.show_folder_encryption(),
        }
    }

    /// Closes a window of the specified type
    ///
    /// Updates the application state and removes tracking references
    /// for the specified window type.
    ///
    /// # Arguments
    /// * `window_type` - The type of window to close
    ///
    /// # Returns
    /// * `Result<(), String>` - Success or error message
    pub fn close_window(&mut self, window_type: WindowType) -> Result<(), String> {
        // Update application state
        {
            let mut app = self.app.lock().map_err(|e| format!("Failed to lock app state: {}", e))?;
            app.close_window(window_type);
        }

        Ok(())
    }

    /// Toggles the open/closed state of a window
    ///
    /// If the window is open, it will be closed. If closed, it will be opened.
    ///
    /// # Arguments
    /// * `window_type` - The type of window to toggle
    ///
    /// # Returns
    /// * `Result<(), String>` - Success or error message
    pub fn toggle_window(&mut self, window_type: WindowType) -> Result<(), String> {
        if self.is_window_open(window_type) {
            self.close_window(window_type)
        } else {
            self.open_window(window_type)
        }
    }

    /// Checks if a window of the specified type is currently open
    ///
    /// # Arguments
    /// * `window_type` - The type of window to check
    ///
    /// # Returns
    /// * `bool` - True if the window is open, false otherwise
    pub fn is_window_open(&self, window_type: WindowType) -> bool {
        // Check application state
        let app = match self.app.lock() {
            Ok(app) => app,
            Err(_) => return false,
        };

        app.is_window_open(window_type)
    }

    /// Gets the title for a window type
    ///
    /// # Arguments
    /// * `window_type` - The type of window
    ///
    /// # Returns
    /// * `&str` - The window title
    pub fn get_window_title(&self, window_type: WindowType) -> String {
        let app = match self.app.lock() {
            Ok(app) => app,
            Err(_) => return "Unknown Window".to_string(),
        };

        app.get_window_title(window_type).to_string()
    }

    /// Gets the number of currently open windows
    ///
    /// # Returns
    /// * `usize` - Number of open windows
    pub fn open_window_count(&self) -> usize {
        let app = match self.app.lock() {
            Ok(app) => app,
            Err(_) => return 0,
        };

        app.windows.values().filter(|w| w.is_open).count()
    }

    /// Closes all open windows
    ///
    /// # Returns
    /// * `Result<(), String>` - Success or error message
    pub fn close_all_windows(&mut self) -> Result<(), String> {
        // Since we don't track individual windows, we just update the app state
        // In a real implementation, this would need to close actual window instances
        let mut app = self.app.lock().map_err(|e| format!("Failed to lock app state: {}", e))?;

        // Close all windows in the app state
        for window_type in [
            WindowType::MainDashboard,
            WindowType::MnemonicManagement,
            WindowType::TextEncryption,
            WindowType::FileEncryption,
            WindowType::DigitalSignatures,
            WindowType::PasswordTools,
            WindowType::BackupManagement,
            WindowType::CloudStorage,
            WindowType::KeyManagement,
            WindowType::Settings,
            WindowType::FolderEncryption,
        ].iter() {
            if let Some(window) = app.windows.get_mut(window_type) {
                window.is_open = false;
            }
        }

        Ok(())
    }

    /// Shows the main dashboard window
    fn show_main_dashboard(&mut self) -> Result<(), String> {
        // Import the generated Slint window type
        use crate::MainDashboard;

        let window = MainDashboard::new()
            .map_err(|e| format!("Failed to create main dashboard window: {}", e))?;

        // Set up window state
        self.setup_main_dashboard_window(&window)?;

        // Show the window
        window.show()
            .map_err(|e| format!("Failed to show main dashboard window: {}", e))?;

        Ok(())
    }

    /// Shows the mnemonic management window
    fn show_mnemonic_management(&mut self) -> Result<(), String> {
        use crate::MnemonicManagement;

        let window = MnemonicManagement::new()
            .map_err(|e| format!("Failed to create mnemonic management window: {}", e))?;

        self.setup_mnemonic_management_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show mnemonic management window: {}", e))?;

        Ok(())
    }

    /// Shows the text encryption window
    fn show_text_encryption(&mut self) -> Result<(), String> {
        use crate::TextEncryptionWindow;

        let window = TextEncryptionWindow::new()
            .map_err(|e| format!("Failed to create text encryption window: {}", e))?;

        self.setup_text_encryption_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show text encryption window: {}", e))?;

        Ok(())
    }

    /// Shows the file encryption window
    fn show_file_encryption(&mut self) -> Result<(), String> {
        use crate::FileEncryptionWindow;

        let window = FileEncryptionWindow::new()
            .map_err(|e| format!("Failed to create file encryption window: {}", e))?;

        self.setup_file_encryption_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show file encryption window: {}", e))?;

        Ok(())
    }

    /// Shows the digital signatures window
    fn show_digital_signatures(&mut self) -> Result<(), String> {
        use crate::DigitalSignaturesWindow;

        let window = DigitalSignaturesWindow::new()
            .map_err(|e| format!("Failed to create digital signatures window: {}", e))?;

        self.setup_digital_signatures_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show digital signatures window: {}", e))?;

        Ok(())
    }

    /// Shows the password tools window
    fn show_password_tools(&mut self) -> Result<(), String> {
        use crate::PasswordToolsWindow;

        let window = PasswordToolsWindow::new()
            .map_err(|e| format!("Failed to create password tools window: {}", e))?;

        self.setup_password_tools_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show password tools window: {}", e))?;

        Ok(())
    }

    /// Shows the backup management window
    fn show_backup_management(&mut self) -> Result<(), String> {
        use crate::BackupManagementWindow;

        let window = BackupManagementWindow::new()
            .map_err(|e| format!("Failed to create backup management window: {}", e))?;

        self.setup_backup_management_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show backup management window: {}", e))?;

        Ok(())
    }

    /// Shows the cloud storage window
    fn show_cloud_storage(&mut self) -> Result<(), String> {
        use crate::CloudStorageWindow;

        let window = CloudStorageWindow::new()
            .map_err(|e| format!("Failed to create cloud storage window: {}", e))?;

        self.setup_cloud_storage_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show cloud storage window: {}", e))?;

        Ok(())
    }

    /// Shows the key management window
    fn show_key_management(&mut self) -> Result<(), String> {
        use crate::KeyManagementWindow;

        let window = KeyManagementWindow::new()
            .map_err(|e| format!("Failed to create key management window: {}", e))?;

        self.setup_key_management_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show key management window: {}", e))?;

        Ok(())
    }

    /// Shows the settings window
    fn show_settings(&mut self) -> Result<(), String> {
        use crate::SettingsWindow;

        let window = SettingsWindow::new()
            .map_err(|e| format!("Failed to create settings window: {}", e))?;

        self.setup_settings_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show settings window: {}", e))?;

        Ok(())
    }

    /// Shows the folder encryption window
    fn show_folder_encryption(&mut self) -> Result<(), String> {
        use crate::FolderEncryptionWindow;

        let window = FolderEncryptionWindow::new()
            .map_err(|e| format!("Failed to create folder encryption window: {}", e))?;

        self.setup_folder_encryption_window(&window)?;

        window.show()
            .map_err(|e| format!("Failed to show folder encryption window: {}", e))?;

        Ok(())
    }

    // Window setup methods - these would contain the callback setup logic
    // For brevity, showing the structure but actual implementations would
    // mirror the setup methods from WindowManager in main.rs

    fn setup_main_dashboard_window(&self, window: &crate::MainDashboard) -> Result<(), String> {
        let weak_window = window.as_weak();
        let app_clone = self.app.clone();

        // Open window callback
        let weak_open = weak_window.clone();
        let app_open = app_clone.clone();
        window.on_open_window(move |window_type: slint::SharedString| {
            let weak = weak_open.clone();
            let app = app_open.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let window_type_str = window_type.to_string();
                    let mut coordinator = WindowCoordinator::new(app);
                    match window_type_str.as_str() {
                        "text-encryption" => {
                            if let Err(e) = coordinator.show_text_encryption() {
                                window.set_last_status(format!("Error opening text encryption: {}", e).into());
                            }
                        }
                        "file-encryption" => {
                            if let Err(e) = coordinator.show_file_encryption() {
                                window.set_last_status(format!("Error opening file encryption: {}", e).into());
                            }
                        }
                        "digital-signatures" => {
                            if let Err(e) = coordinator.show_digital_signatures() {
                                window.set_last_status(format!("Error opening digital signatures: {}", e).into());
                            }
                        }
                        "folder-encryption" => {
                            if let Err(e) = coordinator.show_folder_encryption() {
                                window.set_last_status(format!("Error opening folder encryption: {}", e).into());
                            }
                        }
                        "password-tools" => {
                            if let Err(e) = coordinator.show_password_tools() {
                                window.set_last_status(format!("Error opening password tools: {}", e).into());
                            }
                        }
                        "backup-management" => {
                            if let Err(e) = coordinator.show_backup_management() {
                                window.set_last_status(format!("Error opening backup management: {}", e).into());
                            }
                        }
                        "cloud-storage" => {
                            if let Err(e) = coordinator.show_cloud_storage() {
                                window.set_last_status(format!("Error opening cloud storage: {}", e).into());
                            }
                        }
                        "key-management" => {
                            if let Err(e) = coordinator.show_key_management() {
                                window.set_last_status(format!("Error opening key management: {}", e).into());
                            }
                        }
                        "mnemonic-management" => {
                            if let Err(e) = coordinator.show_mnemonic_management() {
                                window.set_last_status(format!("Error opening mnemonic management: {}", e).into());
                            }
                        }
                        _ => {
                            window.set_last_status(format!("Unknown window type: {}", window_type_str).into());
                        }
                    }
                }
            }).unwrap();
        });

        // Clear status callback
        let weak_clear = weak_window.clone();
        window.on_clear_status(move || {
            let weak = weak_clear.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    window.set_last_status("".into());
                }
            }).unwrap();
        });

        // Copy public key callback
        let weak_copy = weak_window.clone();
        let app_copy = app_clone.clone();
        window.on_copy_public_key(move || {
            let weak = weak_copy.clone();
            let app = app_copy.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let app_lock = app.lock().unwrap();
                    if let Some(sensitive_data) = &app_lock.sensitive_data {
                        let current = sensitive_data.current();

                        // Create a compact representation of public keys
                        use sha2::{Sha256, Digest};
                        let mut hasher = Sha256::new();
                        hasher.update(&current.kyber_keys.public);
                        hasher.update(&current.dilithium_keys.public);
                        let hash = hasher.finalize();

                        let compact_id = hex::encode(&hash[..16]);
                        let public_key_info = format!("cybou:{}\nKyber: {}\nDilithium: {}",
                            compact_id,
                            hex::encode(&current.kyber_keys.public),
                            hex::encode(&current.dilithium_keys.public)
                        );

                        match clipboard::ClipboardContext::new() {
                            Ok(mut ctx) => {
                                match ctx.set_contents(public_key_info) {
                                    Ok(_) => window.set_last_status("Public keys copied to clipboard".into()),
                                    Err(e) => window.set_last_status(format!("Error copying to clipboard: {}", e).into()),
                                }
                            }
                            Err(e) => window.set_last_status(format!("Error accessing clipboard: {}", e).into()),
                        }
                    } else {
                        window.set_last_status("No keys loaded".into());
                    }
                }
            }).unwrap();
        });

        // Save public key callback
        let weak_save = weak_window.clone();
        let app_save = app_clone.clone();
        window.on_save_public_key(move || {
            let weak = weak_save.clone();
            let app = app_save.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let app_lock = app.lock().unwrap();
                    if let Some(sensitive_data) = &app_lock.sensitive_data {
                        let current = sensitive_data.current();

                        // Create .cyboukey file content
                        let public_key_data = format!("cybou-public-key-v1\n{}\n{}",
                            hex::encode(&current.kyber_keys.public),
                            hex::encode(&current.dilithium_keys.public)
                        );

                        // Use rfd crate for file dialog
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Save Public Key File")
                            .set_file_name("public_key.cyboukey")
                            .save_file()
                        {
                            match std::fs::write(&path, &public_key_data) {
                                Ok(_) => window.set_last_status(format!("Public key saved to: {}", path.display()).into()),
                                Err(e) => window.set_last_status(format!("Error saving file: {}", e).into()),
                            }
                        } else {
                            window.set_last_status("Save cancelled".into());
                        }
                    } else {
                        window.set_last_status("No keys loaded".into());
                    }
                }
            }).unwrap();
        });

        Ok(())
    }

    fn setup_mnemonic_management_window(&self, window: &crate::MnemonicManagement) -> Result<(), String> {
        let weak_window = window.as_weak();
        let app_clone = self.app.clone();

        // Generate mnemonic callback
        let weak_generate = weak_window.clone();
        window.on_generate_mnemonic(move |word_count: i32| {
            let weak = weak_generate.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    use bip39::{Mnemonic, Language};

                    // Generate entropy based on word count
                    // 12 words = 128 bits = 16 bytes
                    // 24 words = 256 bits = 32 bytes
                    let entropy_size = if word_count == 24 { 32 } else { 16 };
                    let mut entropy = vec![0u8; entropy_size];
                    rand::Rng::fill(&mut rand::thread_rng(), &mut entropy[..]);

                    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
                    let mnemonic_str = mnemonic.to_string();
                    window.set_mnemonic_input(mnemonic_str.clone().into());

                    // Manually trigger validation since setting text programmatically doesn't fire the edited callback
                    let is_valid = bip39::Mnemonic::parse(&mnemonic_str).is_ok();
                    window.set_is_valid(is_valid);

                    if is_valid {
                        // Automatically derive keys when mnemonic is valid
                        let mut temp_app = crate::types::App::default();
                        temp_app.mnemonic_input = mnemonic_str.clone();

                        if temp_app.validate_and_derive_keys() {
                            // Store the keys in the global SENSITIVE_DATA
                            if let Some(sensitive_data) = temp_app.sensitive_data {
                                *crate::SENSITIVE_DATA.lock().unwrap() = Some(sensitive_data);

                                // Generate compact public key identifier
                                let sensitive_data_lock = crate::SENSITIVE_DATA.lock().unwrap();
                                let current = sensitive_data_lock.as_ref().unwrap().current();

                                // Create a hash of the public keys for identification
                                use sha2::{Sha256, Digest};
                                let mut hasher = Sha256::new();
                                hasher.update(&current.kyber_keys.public);
                                hasher.update(&current.dilithium_keys.public);
                                let hash = hasher.finalize();

                                // Take first 8 bytes and encode as hex for compact display
                                let compact_id = hex::encode(&hash[..8]);
                                let public_key_display = format!("cybou:{}", &compact_id[..16]);

                                window.set_public_key_display(public_key_display.into());
                                window.set_keys_loaded(true);
                                window.set_status_text("Keys derived and loaded ✓".into());
                            } else {
                                window.set_status_text("Failed to create sensitive data".into());
                                window.set_keys_loaded(false);
                                window.set_public_key_display("".into());
                            }
                        } else {
                            window.set_status_text("Failed to derive keys from valid mnemonic".into());
                            window.set_keys_loaded(false);
                            window.set_public_key_display("".into());
                        }
                    } else {
                        window.set_status_text("Invalid mnemonic phrase ✗".into());
                        window.set_keys_loaded(false);
                        window.set_public_key_display("".into());
                    }
                }
            }).unwrap();
        });

        // Validate mnemonic callback
        let weak_validate = weak_window.clone();
        window.on_validate_mnemonic(move |mnemonic_text: slint::SharedString| {
            let weak = weak_validate.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let mnemonic_input = mnemonic_text.to_string();
                    if mnemonic_input.is_empty() {
                        window.set_status_text("Enter your 12 or 24-word BIP39 mnemonic phrase".into());
                        window.set_is_valid(false);
                        window.set_keys_loaded(false);
                        window.set_public_key_display("".into());
                        return;
                    }

                    let is_valid = bip39::Mnemonic::parse(&mnemonic_input).is_ok();
                    window.set_is_valid(is_valid);

                    if is_valid {
                        // Automatically derive keys when mnemonic is valid
                        let mut temp_app = crate::types::App::default();
                        temp_app.mnemonic_input = mnemonic_input.clone();

                        if temp_app.validate_and_derive_keys() {
                            // Store the keys in the global SENSITIVE_DATA
                            if let Some(sensitive_data) = temp_app.sensitive_data {
                                *crate::SENSITIVE_DATA.lock().unwrap() = Some(sensitive_data);

                                // Generate compact public key identifier
                                let sensitive_data_lock = crate::SENSITIVE_DATA.lock().unwrap();
                                let current = sensitive_data_lock.as_ref().unwrap().current();

                                // Create a hash of the public keys for identification
                                use sha2::{Sha256, Digest};
                                let mut hasher = Sha256::new();
                                hasher.update(&current.kyber_keys.public);
                                hasher.update(&current.dilithium_keys.public);
                                let hash = hasher.finalize();

                                // Take first 8 bytes and encode as hex for compact display
                                let compact_id = hex::encode(&hash[..8]);
                                let public_key_display = format!("cybou:{}", &compact_id[..16]);

                                window.set_public_key_display(public_key_display.into());
                                window.set_keys_loaded(true);
                                window.set_status_text("Keys derived and loaded ✓".into());
                            } else {
                                window.set_status_text("Failed to create sensitive data".into());
                                window.set_keys_loaded(false);
                                window.set_public_key_display("".into());
                            }
                        } else {
                            window.set_status_text("Failed to derive keys from valid mnemonic".into());
                            window.set_keys_loaded(false);
                            window.set_public_key_display("".into());
                        }
                    } else {
                        window.set_status_text("Invalid mnemonic phrase ✗".into());
                        window.set_keys_loaded(false);
                        window.set_public_key_display("".into());
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
                    // Keys are already derived and loaded when mnemonic became valid
                    // Just set the global state and transition to dashboard

                    // The keys are already in the SENSITIVE_DATA from the validation callback
                    // Just make sure dashboard opens immediately

                    // Close mnemonic window and show main dashboard immediately
                    let app = std::sync::Arc::new(std::sync::Mutex::new(crate::types::App::default()));
                    let mut coordinator = WindowCoordinator::new(app);
                    if let Err(e) = coordinator.show_main_dashboard() {
                        window.set_status_text(format!("Error opening dashboard: {}", e).into());
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
                    let keys_loaded = window.get_keys_loaded();
                    if keys_loaded {
                        // Copy public key identifier when keys are loaded
                        let public_key = window.get_public_key_display().to_string();
                        if public_key.is_empty() {
                            window.set_status_text("No public key to copy".into());
                            return;
                        }
                        match clipboard::ClipboardContext::new() {
                            Ok(mut ctx) => {
                                match ctx.set_contents(public_key) {
                                    Ok(_) => window.set_status_text("Public key identifier copied to clipboard".into()),
                                    Err(_) => window.set_status_text("Failed to copy to clipboard".into()),
                                }
                            }
                            Err(_) => window.set_status_text("Clipboard not available".into()),
                        }
                    } else {
                        // Copy mnemonic when keys are not loaded
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
                    window.set_status_text("Enter your 12 or 24-word BIP39 mnemonic phrase".into());
                    window.set_is_valid(false);
                    window.set_keys_loaded(false);
                    window.set_public_key_display("".into());
                }
            }).unwrap();
        });

        // Show help callback
        let weak_help = weak_window.clone();
        window.on_show_help(move |help_topic: slint::SharedString| {
            let weak = weak_help.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    let help_message = match help_topic.as_str() {
                        "mnemonic-management" => "🔑 Mnemonic Management\n\nThis window allows you to enter or generate a BIP39 mnemonic phrase to derive your cryptographic keys.\n\n• Enter your existing mnemonic or generate a new one\n• The system automatically validates your input\n• Once valid, click Continue to load your keys",
                        "mnemonic-input" => "📝 Mnemonic Input\n\nEnter your 12 or 24-word BIP39 mnemonic phrase. This phrase is used to securely derive all your cryptographic keys.\n\n• Words must be from the BIP39 word list\n• Use spaces between words\n• The phrase is case-insensitive\n• Keep this phrase secure and private",
                        _ => "Help topic not found"
                    };

                    // For now, just show in status. In a real app, this would open a modal/popup
                    window.set_status_text(help_message.into());
                }
            }).unwrap();
        });

        Ok(())
    }

    fn setup_text_encryption_window(&self, window: &crate::TextEncryptionWindow) -> Result<(), String> {
        let weak_window = window.as_weak();
        let app_clone = self.app.clone();

        // Encrypt callback
        let weak_encrypt = weak_window.clone();
        let app_encrypt = app_clone.clone();
        window.on_encrypt(move || {
            let weak = weak_encrypt.clone();
            let app = app_encrypt.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Get input text
                    let input_text = window.get_input_text().to_string();

                    // Create a temporary app for crypto operations
                    let mut temp_app = crate::types::App::default();
                    temp_app.text_input = input_text;
                    temp_app.encrypt_text();
                    window.set_output_text(temp_app.text_output.into());
                    window.set_status(temp_app.last_status.into());
                }
            }).unwrap();
        });

        // Decrypt callback
        let weak_decrypt = weak_window.clone();
        let app_decrypt = app_clone.clone();
        window.on_decrypt(move || {
            let weak = weak_decrypt.clone();
            let app = app_decrypt.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Get input text
                    let input_text = window.get_input_text().to_string();

                    // Create a temporary app for crypto operations
                    let mut temp_app = crate::types::App::default();
                    temp_app.text_input = input_text;
                    temp_app.decrypt_text();
                    window.set_output_text(temp_app.text_output.into());
                    window.set_status(temp_app.last_status.into());
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

        Ok(())
    }

    fn setup_file_encryption_window(&self, _window: &crate::FileEncryptionWindow) -> Result<(), String> {
        // TODO: Implement file encryption window setup with callbacks
        Ok(())
    }

    fn setup_digital_signatures_window(&self, _window: &crate::DigitalSignaturesWindow) -> Result<(), String> {
        // TODO: Implement digital signatures window setup with callbacks
        Ok(())
    }

    fn setup_password_tools_window(&self, window: &crate::PasswordToolsWindow) -> Result<(), String> {
        let weak_window = window.as_weak();
        let app_clone = self.app.clone();

        // Generate password callback
        let weak_generate = weak_window.clone();
        window.on_generate_password(move || {
            let weak = weak_generate.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // Get password generation options
                    let length = window.get_password_length() as usize;
                    let include_uppercase = window.get_use_uppercase();
                    let include_lowercase = window.get_use_lowercase();
                    let include_numbers = window.get_use_numbers();
                    let include_symbols = window.get_use_symbols();

                    // Create a temporary app for password generation
                    let mut temp_app = crate::types::App::default();
                    temp_app.password_length = length;
                    temp_app.include_uppercase = include_uppercase;
                    temp_app.include_lowercase = include_lowercase;
                    temp_app.include_numbers = include_numbers;
                    temp_app.include_symbols = include_symbols;
                    temp_app.generate_secure_password();
                    window.set_generated_password(temp_app.text_output.into());
                    window.set_status(temp_app.last_status.into());
                }
            }).unwrap();
        });

        // Check strength callback
        let weak_check = weak_window.clone();
        window.on_check_strength(move || {
            let weak = weak_check.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    // For now, check the generated password
                    let password = window.get_generated_password().to_string();
                    if password.is_empty() {
                        window.set_status("No password to check".into());
                        return;
                    }

                    // Create a temporary app for password assessment
                    let mut temp_app = crate::types::App::default();
                    temp_app.password_input = password;
                    temp_app.assess_password_strength();
                    window.set_password_strength(temp_app.text_output.into());
                    window.set_status(temp_app.last_status.into());
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

                    match clipboard::ClipboardContext::new() {
                        Ok(mut ctx) => {
                            match ctx.set_contents(password) {
                                Ok(_) => window.set_status("Password copied to clipboard".into()),
                                Err(e) => window.set_status(format!("Error copying to clipboard: {}", e).into()),
                            }
                        }
                        Err(e) => window.set_status(format!("Error accessing clipboard: {}", e).into()),
                    }
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
                    window.set_password_strength("Weak".into());
                    window.set_status("Ready".into());
                }
            }).unwrap();
        });

        Ok(())
    }

    fn setup_backup_management_window(&self, _window: &crate::BackupManagementWindow) -> Result<(), String> {
        // TODO: Implement backup management window setup with callbacks
        Ok(())
    }

    fn setup_cloud_storage_window(&self, _window: &crate::CloudStorageWindow) -> Result<(), String> {
        // TODO: Implement cloud storage window setup with callbacks
        Ok(())
    }

    fn setup_key_management_window(&self, _window: &crate::KeyManagementWindow) -> Result<(), String> {
        // TODO: Implement key management window setup with callbacks
        Ok(())
    }

    fn setup_settings_window(&self, _window: &crate::SettingsWindow) -> Result<(), String> {
        // TODO: Implement settings window setup with callbacks
        Ok(())
    }

    fn setup_folder_encryption_window(&self, _window: &crate::FolderEncryptionWindow) -> Result<(), String> {
        // TODO: Implement folder encryption window setup with callbacks
        Ok(())
    }
}

/// Utility functions for window management
pub mod utils {
    use super::*;

    /// Creates a default window coordinator with a new application state
    ///
    /// # Returns
    /// * `WindowCoordinator` - New coordinator with default app state
    pub fn create_default_coordinator() -> WindowCoordinator {
        let app = std::sync::Arc::new(std::sync::Mutex::new(App::default()));
        WindowCoordinator::new(app)
    }

    /// Gets the recommended window size for a given window type
    ///
    /// # Arguments
    /// * `window_type` - The type of window
    ///
    /// # Returns
    /// * `(u32, u32)` - Recommended width and height
    pub fn get_recommended_size(window_type: WindowType) -> (u32, u32) {
        match window_type {
            WindowType::MainDashboard => (800, 600),
            WindowType::MnemonicManagement => (700, 500),
            WindowType::TextEncryption => (700, 500),
            WindowType::FileEncryption => (700, 500),
            WindowType::DigitalSignatures => (700, 500),
            WindowType::PasswordTools => (600, 400),
            WindowType::BackupManagement => (800, 600),
            WindowType::CloudStorage => (800, 600),
            WindowType::KeyManagement => (700, 500),
            WindowType::Settings => (600, 500),
            WindowType::FolderEncryption => (700, 500),
        }
    }

    /// Checks if a window type supports multiple instances
    ///
    /// # Arguments
    /// * `window_type` - The type of window
    ///
    /// # Returns
    /// * `bool` - True if multiple instances are allowed
    pub fn allows_multiple_instances(window_type: WindowType) -> bool {
        // Currently, no window types allow multiple instances
        // This could be extended in the future for certain window types
        match window_type {
            _ => false,
        }
    }
}