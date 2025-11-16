//! Window management module
//!
//! This module handles the multi-window GUI architecture, allowing different
//! application features to be displayed in separate windows.

use crate::types::App;

/// Represents different types of windows that can be opened
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum WindowType {
    Main,
    TextEncryption,
    FileEncryption,
    DigitalSignatures,
    FolderEncryption,
    PasswordTools,
    BackupManagement,
    CloudStorage,
    KeyManagement,
    Settings,
}

/// Represents the state of a window
#[derive(Clone)]
pub struct WindowState {
    pub window_type: WindowType,
    pub is_open: bool,
    pub position: Option<(f32, f32)>,
    pub size: Option<(f32, f32)>,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            window_type: WindowType::Main,
            is_open: false,
            position: None,
            size: None,
        }
    }
}

impl WindowState {
    pub fn new(window_type: WindowType) -> Self {
        Self {
            window_type,
            is_open: false,
            position: None,
            size: None,
        }
    }

    pub fn title(&self) -> &'static str {
        match self.window_type {
            WindowType::Main => "Cybou - Dashboard",
            WindowType::TextEncryption => "Text Encryption",
            WindowType::FileEncryption => "File Encryption",
            WindowType::DigitalSignatures => "Digital Signatures",
            WindowType::FolderEncryption => "Folder Encryption",
            WindowType::PasswordTools => "Password Tools",
            WindowType::BackupManagement => "Backup Management",
            WindowType::CloudStorage => "Cloud Storage",
            WindowType::KeyManagement => "Key Management",
            WindowType::Settings => "Settings",
        }
    }
}

impl App {
    /// Initializes the window management system
    pub fn init_windows(&mut self) {
        if self.windows.is_empty() {
            // Create window states for all window types
            self.windows.insert(WindowType::Main, WindowState::new(WindowType::Main));
            self.windows.insert(WindowType::TextEncryption, WindowState::new(WindowType::TextEncryption));
            self.windows.insert(WindowType::FileEncryption, WindowState::new(WindowType::FileEncryption));
            self.windows.insert(WindowType::DigitalSignatures, WindowState::new(WindowType::DigitalSignatures));
            self.windows.insert(WindowType::FolderEncryption, WindowState::new(WindowType::FolderEncryption));
            self.windows.insert(WindowType::PasswordTools, WindowState::new(WindowType::PasswordTools));
            self.windows.insert(WindowType::BackupManagement, WindowState::new(WindowType::BackupManagement));
            self.windows.insert(WindowType::CloudStorage, WindowState::new(WindowType::CloudStorage));
            self.windows.insert(WindowType::KeyManagement, WindowState::new(WindowType::KeyManagement));
            self.windows.insert(WindowType::Settings, WindowState::new(WindowType::Settings));

            // Main window is always open
            if let Some(main_window) = self.windows.get_mut(&WindowType::Main) {
                main_window.is_open = true;
            }
        }
    }

    /// Opens a specific window
    pub fn open_window(&mut self, window_type: WindowType) {
        if let Some(window) = self.windows.get_mut(&window_type) {
            window.is_open = true;
        }
    }

    /// Closes a specific window
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
}