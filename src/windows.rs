//! Window management module
//!
//! This module handles the multi-window GUI architecture, allowing different
//! application features to be displayed in separate windows.

use crate::types::App;
use eframe::egui::{Context, Window};

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
    pub position: Option<egui::Pos2>,
    pub size: Option<egui::Vec2>,
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

    /// Renders all open windows
    pub fn render_windows(&mut self, ctx: &Context) {
        // Apply current theme
        self.apply_theme(ctx);

        // Collect window states that need to be rendered
        let mut windows_to_render = Vec::new();
        for (window_type, window_state) in &self.windows {
            if window_state.is_open {
                windows_to_render.push((window_type.clone(), window_state.title().to_string()));
            }
        }

        // Render windows
        for (window_type, title) in windows_to_render {
            match window_type {
                WindowType::Main => {
                    let mut open = true;
                    Window::new(&title)
                        .open(&mut open)
                        .default_size([800.0, 600.0])
                        .show(ctx, |ui| {
                            self.show_main_dashboard(ui);
                        });
                    if let Some(window) = self.windows.get_mut(&window_type) {
                        window.is_open = open;
                    }
                }
                _ => {
                    let mut open = true;
                    Window::new(&title)
                        .open(&mut open)
                        .default_size([600.0, 400.0])
                        .show(ctx, |ui| {
                            self.render_window_content(window_type.clone(), ui);
                        });
                    if let Some(window) = self.windows.get_mut(&window_type) {
                        window.is_open = open;
                    }
                }
            }
        }
    }

    /// Renders the content for a specific window type
    pub fn render_window_content(&mut self, window_type: WindowType, ui: &mut eframe::egui::Ui) {
        match window_type {
            WindowType::TextEncryption => self.show_text_encrypt_decrypt(ui),
            WindowType::FileEncryption => self.show_file_encrypt_decrypt(ui),
            WindowType::DigitalSignatures => self.show_sign_verify(ui),
            WindowType::FolderEncryption => self.show_folder_encrypt(ui),
            WindowType::PasswordTools => self.show_password_tools(ui),
            WindowType::BackupManagement => self.show_backups(ui),
            WindowType::CloudStorage => self.show_cloud_storage(ui),
            WindowType::KeyManagement => self.show_key_management(ui),
            WindowType::Settings => self.show_settings(ui),
            WindowType::Main => {} // Main window is handled separately
        }
    }

    /// Handles keyboard shortcuts for opening windows
    pub fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        // Ctrl+T: Text Encryption
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::T)) {
            self.toggle_window(WindowType::TextEncryption);
        }
        // Ctrl+F: File Encryption
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::F)) {
            self.toggle_window(WindowType::FileEncryption);
        }
        // Ctrl+S: Digital Signatures
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::S)) {
            self.toggle_window(WindowType::DigitalSignatures);
        }
        // Ctrl+D: Folder Encryption
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::D)) {
            self.toggle_window(WindowType::FolderEncryption);
        }
        // Ctrl+P: Password Tools
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::P)) {
            self.toggle_window(WindowType::PasswordTools);
        }
        // Ctrl+B: Backup Management
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::B)) {
            self.toggle_window(WindowType::BackupManagement);
        }
        // Ctrl+C: Cloud Storage
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::C)) {
            self.toggle_window(WindowType::CloudStorage);
        }
        // Ctrl+K: Key Management
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::K)) {
            self.toggle_window(WindowType::KeyManagement);
        }
        // Ctrl+G: Settings
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::G)) {
            self.toggle_window(WindowType::Settings);
        }
        // Ctrl+M: Main Dashboard (focus)
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::M)) {
            self.open_window(WindowType::Main);
        }
    }

    /// Shows the main dashboard with menu and aggregated stats
    pub fn show_main_dashboard(&mut self, ui: &mut eframe::egui::Ui) {
        // Handle keyboard shortcuts
        self.handle_keyboard_shortcuts(ui.ctx());

        // Apply current theme
        self.apply_theme(ui.ctx());

        ui.vertical(|ui| {
            // Header with title
            ui.horizontal(|ui| {
                ui.heading("🔐 Cybou - Secure Cryptography Dashboard");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("ℹ️ About").clicked() {
                        self.show_about_modal = true;
                    }
                });
            });

            ui.separator();

            // Main menu bar
            ui.group(|ui| {
                ui.label("📋 Main Menu - Click to open windows, or use keyboard shortcuts:");
                ui.horizontal_wrapped(|ui| {
                    let menu_items = [
                        ("📝 Text Encryption (Ctrl+T)", WindowType::TextEncryption),
                        ("📁 File Encryption (Ctrl+F)", WindowType::FileEncryption),
                        ("✍️ Digital Signatures (Ctrl+S)", WindowType::DigitalSignatures),
                        ("📂 Folder Encryption (Ctrl+D)", WindowType::FolderEncryption),
                        ("🔧 Password Tools (Ctrl+P)", WindowType::PasswordTools),
                        ("💾 Backup Management (Ctrl+B)", WindowType::BackupManagement),
                        ("☁️ Cloud Storage (Ctrl+C)", WindowType::CloudStorage),
                        ("🔑 Key Management (Ctrl+K)", WindowType::KeyManagement),
                        ("⚙️ Settings (Ctrl+G)", WindowType::Settings),
                    ];

                    for (label, window_type) in menu_items {
                        let is_open = self.is_window_open(window_type.clone());
                        let button_text = if is_open { format!("{} ✓", label) } else { label.to_string() };

                        if ui.button(button_text).clicked() {
                            self.toggle_window(window_type);
                        }
                    }
                });
            });

            ui.separator();

            // Dashboard content
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.show_dashboard_content(ui);
            });

            ui.separator();

            // Status bar
            ui.horizontal(|ui| {
                ui.label("📊 Status:");
                ui.colored_label(
                    if self.last_status.contains("success") || self.last_status.contains("Success") {
                        egui::Color32::from_rgb(0, 150, 0)
                    } else if self.last_status.contains("failed") || self.last_status.contains("Failed") || self.last_status.contains("error") {
                        egui::Color32::from_rgb(200, 0, 0)
                    } else {
                        egui::Color32::from_rgb(100, 100, 100)
                    },
                    &self.last_status
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🗑️ Clear").clicked() {
                        self.last_status.clear();
                    }
                });
            });
        });

        // Show about modal if requested
        if self.show_about_modal {
            self.show_about_modal(ui.ctx());
        }
    }

    /// Shows the dashboard content with aggregated statistics
    pub fn show_dashboard_content(&mut self, ui: &mut eframe::egui::Ui) {
        ui.heading("📊 Application Dashboard");

        ui.add_space(10.0);

        // Quick Actions Section
        ui.group(|ui| {
            ui.label("🚀 Quick Actions");
            ui.horizontal_wrapped(|ui| {
                if ui.button("🔐 Encrypt Text").clicked() {
                    self.open_window(WindowType::TextEncryption);
                }
                if ui.button("📁 Encrypt File").clicked() {
                    self.open_window(WindowType::FileEncryption);
                }
                if ui.button("✍️ Sign Message").clicked() {
                    self.open_window(WindowType::DigitalSignatures);
                }
                if ui.button("🔑 Generate Password").clicked() {
                    self.open_window(WindowType::PasswordTools);
                }
                if ui.button("💾 Start Backup").clicked() {
                    self.open_window(WindowType::BackupManagement);
                }
            });
        });

        ui.add_space(15.0);

        // System Status Section
        ui.group(|ui| {
            ui.label("🔄 System Status");

            // Key Status
            ui.horizontal(|ui| {
                ui.label("🔑 Cryptographic Keys:");
                if self.sensitive_data.is_some() {
                    ui.colored_label(egui::Color32::GREEN, "Loaded ✓");
                } else {
                    ui.colored_label(egui::Color32::RED, "Not Loaded ✗");
                }
            });

            // Backup Status
            ui.horizontal(|ui| {
                ui.label("💾 Backup Service:");
                if self.backup_active {
                    ui.colored_label(egui::Color32::GREEN, "Active ✓");
                    if let Some(count_ref) = &self.backup_file_count_ref {
                        let count = *count_ref.lock().unwrap();
                        ui.label(format!("({} files backed up)", count));
                    }
                } else {
                    ui.colored_label(egui::Color32::GRAY, "Inactive");
                }
            });

            // Cloud Status
            ui.horizontal(|ui| {
                ui.label("☁️ Cloud Storage:");
                match self.cloud_provider {
                    crate::types::CloudProvider::None => {
                        ui.colored_label(egui::Color32::GRAY, "Not Configured");
                    }
                    crate::types::CloudProvider::AWS => {
                        if self.s3_client.is_some() {
                            ui.colored_label(egui::Color32::GREEN, "AWS S3 Connected ✓");
                        } else {
                            ui.colored_label(egui::Color32::YELLOW, "AWS S3 Configured");
                        }
                    }
                    crate::types::CloudProvider::GCP => {
                        ui.colored_label(egui::Color32::YELLOW, "GCP (Coming Soon)");
                    }
                    crate::types::CloudProvider::Azure => {
                        ui.colored_label(egui::Color32::YELLOW, "Azure (Coming Soon)");
                    }
                }
            });

            // Open Windows
            ui.horizontal(|ui| {
                ui.label("🖼️ Open Windows:");
                let open_count = self.windows.values().filter(|w| w.is_open).count();
                ui.label(format!("{} of {}", open_count, self.windows.len()));
            });
        });

        ui.add_space(15.0);

        // Statistics Section
        ui.group(|ui| {
            ui.label("📈 Application Statistics");

            if let Some(data) = &self.sensitive_data {
                let stats = data.get_key_statistics();

                ui.horizontal(|ui| {
                    ui.label("Key Versions:");
                    ui.label(format!("{}", stats.total_versions));
                });

                ui.horizontal(|ui| {
                    ui.label("Current Key ID:");
                    ui.label(format!("{}", stats.current_version_id));
                });

                if let (Some(oldest), Some(newest)) = (stats.oldest_version, stats.newest_version) {
                    let age_days = newest.duration_since(oldest).unwrap_or_default().as_secs() / 86400;
                    ui.horizontal(|ui| {
                        ui.label("Key Age:");
                        ui.label(format!("{} days", age_days));
                    });
                }
            } else {
                ui.colored_label(egui::Color32::YELLOW, "No cryptographic keys loaded");
            }

            ui.horizontal(|ui| {
                ui.label("Watched Folders:");
                ui.label(format!("{}", self.watched_folders.len()));
            });

            ui.horizontal(|ui| {
                ui.label("Backup Path:");
                if self.backup_path.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "Not Set");
                } else {
                    ui.colored_label(egui::Color32::GREEN, "Configured ✓");
                }
            });
        });

        ui.add_space(15.0);

        // Recent Activity Section
        ui.group(|ui| {
            ui.label("📋 Recent Activity");
            ui.label("Last operation:");
            ui.label(&self.last_status);

            if !self.text_output.is_empty() {
                ui.label("Output:");
                ui.label(&self.text_output);
            }
        });

        ui.add_space(15.0);

        // Tips Section
        ui.group(|ui| {
            ui.label("💡 Quick Tips");
            ui.label("• Use the menu above to open specific tools");
            ui.label("• Check system status for service availability");
            ui.label("• Monitor backup activity in the status bar");
            ui.label("• Keep your cryptographic keys secure");
        });
    }
}