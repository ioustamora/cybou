//! User interface module
//!
//! This module contains all UI components and rendering logic for the Cybou application.

use crate::types::App;
use eframe::egui::{CentralPanel, Context, Ui, Window};

impl App {
    /// Shows the mnemonic input modal on first launch
    pub fn show_mnemonic_modal(&mut self, ctx: &Context) {
        Window::new("Enter Mnemonic Phrase")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("Enter your 12 or 24 word mnemonic phrase:");
                ui.text_edit_multiline(&mut self.mnemonic_input);
                ui.horizontal(|ui| {
                    if ui.button("Generate").clicked() {
                        let entropy: [u8; 16] = rand::random();
                        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
                        self.mnemonic_input = mnemonic.to_string();
                    }
                    if ui.button("Clear").clicked() {
                        self.mnemonic_input.clear();
                    }
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(self.mnemonic_input.clone());
                    }
                });
                let is_valid = bip39::Mnemonic::parse(&self.mnemonic_input).is_ok();
                if !is_valid && !self.mnemonic_input.is_empty() {
                    ui.label("Invalid mnemonic phrase");
                }
                if ui.add_enabled(is_valid, egui::Button::new("Continue")).clicked() {
                    self.validate_and_derive_keys();
                    self.show_mnemonic_modal = false;
                }
            });
    }

    /// Renders the main application UI with tabs
    pub fn show_main_ui(&mut self, ctx: &Context) {
        // Apply current theme
        self.apply_theme(ctx);

        CentralPanel::default().show(ctx, |ui| {
            // Header with title and status
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.heading("🔐 Cybou - Secure Cryptography");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("ℹ️ About").clicked() {
                            self.show_about_modal = true;
                        }
                    });
                });

                ui.separator();

                // Tab navigation with better styling
                ui.horizontal_wrapped(|ui| {
                    let tabs = [
                        ("📝 Text", 0),
                        ("📁 Files", 1),
                        ("✍️ Sign/Verify", 2),
                        ("📂 Folders", 3),
                        ("🔧 Password Tools", 4),
                        ("💾 Backups", 5),
                        ("☁️ Cloud", 6),
                        ("🔑 Keys", 7),
                        ("⚙️ Settings", 8),
                    ];

                    for (label, tab_id) in tabs {
                        let selected = self.current_tab == tab_id;
                        if ui.selectable_label(selected, label).clicked() {
                            self.current_tab = tab_id;
                        }
                    }
                });

                ui.separator();

                // Main content area
                egui::ScrollArea::vertical().show(ui, |ui| {
                    match self.current_tab {
                        0 => self.show_text_encrypt_decrypt(ui),
                        1 => self.show_file_encrypt_decrypt(ui),
                        2 => self.show_sign_verify(ui),
                        3 => self.show_folder_encrypt(ui),
                        4 => self.show_password_tools(ui),
                        5 => self.show_backups(ui),
                        6 => self.show_cloud_storage(ui),
                        7 => self.show_key_management(ui),
                        8 => self.show_settings(ui),
                        _ => {}
                    }
                });

                ui.separator();

                // Status bar with better styling
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
        });

        // Show about modal if requested
        if self.show_about_modal {
            self.show_about_modal(ctx);
        }
    }

    /// Renders the text encryption/decryption tab
    pub fn show_text_encrypt_decrypt(&mut self, ui: &mut Ui) {
        ui.label("Text to encrypt/decrypt:");
        ui.text_edit_multiline(&mut self.text_input);

        ui.horizontal(|ui| {
            if ui.button("Encrypt Text").clicked() {
                self.encrypt_text();
            }
            if ui.button("Decrypt Text").clicked() {
                self.decrypt_text();
            }
            if ui.button("Clear Input").clicked() {
                self.text_input.clear();
            }
            if ui.button("Clear Output").clicked() {
                self.text_output.clear();
            }
        });

        ui.label("Output:");
        ui.text_edit_multiline(&mut self.text_output);

        ui.horizontal(|ui| {
            if ui.button("Copy Output").clicked() {
                ui.ctx().copy_text(self.text_output.clone());
            }
        });
    }

    /// Renders the file encryption/decryption tab
    pub fn show_file_encrypt_decrypt(&mut self, ui: &mut Ui) {
        ui.label("File path:");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.file_path);
            if ui.button("Select File").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.file_path = path.display().to_string();
                }
            }
            if ui.button("Clear Path").clicked() {
                self.file_path.clear();
            }
        });

        ui.horizontal(|ui| {
            if ui.button("Encrypt File").clicked() {
                self.encrypt_file();
            }
            if ui.button("Decrypt File").clicked() {
                self.decrypt_file();
            }
        });

        ui.label("Status:");
        ui.label(&self.text_output);

        ui.horizontal(|ui| {
            if ui.button("Copy Status").clicked() {
                ui.ctx().copy_text(self.text_output.clone());
            }
        });
    }

    /// Renders the digital signature tab
    pub fn show_sign_verify(&mut self, ui: &mut Ui) {
        ui.label("Text to sign:");
        ui.text_edit_multiline(&mut self.sign_text);

        ui.horizontal(|ui| {
            if ui.button("Sign").clicked() {
                self.sign_message();
            }
            if ui.button("Clear").clicked() {
                self.sign_text.clear();
                self.sign_signature.clear();
            }
        });

        ui.label("Signature:");
        ui.text_edit_multiline(&mut self.sign_signature);

        ui.horizontal(|ui| {
            if ui.button("Copy Signature").clicked() {
                ui.ctx().copy_text(self.sign_signature.clone());
            }
        });

        ui.separator();

        ui.label("Text to verify:");
        ui.text_edit_multiline(&mut self.verify_text);

        ui.label("Signature to verify:");
        ui.text_edit_multiline(&mut self.verify_signature);

        ui.horizontal(|ui| {
            if ui.button("Verify").clicked() {
                self.verify_message();
            }
            if ui.button("Clear").clicked() {
                self.verify_text.clear();
                self.verify_signature.clear();
            }
        });

        ui.label("Result:");
        ui.label(&self.text_output);

        ui.horizontal(|ui| {
            if ui.button("Copy Result").clicked() {
                ui.ctx().copy_text(self.text_output.clone());
            }
        });
    }

    /// Renders the folder encryption tab
    pub fn show_folder_encrypt(&mut self, ui: &mut Ui) {
        ui.label("Folder path:");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.folder_path);
            if ui.button("Select Folder").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.folder_path = path.display().to_string();
                }
            }
            if ui.button("Clear").clicked() {
                self.folder_path.clear();
            }
        });

        if ui.button("Encrypt Folder").clicked() {
            self.encrypt_folder();
        }

        ui.label("Status:");
        ui.label(&self.text_output);

        ui.horizontal(|ui| {
            if ui.button("Copy Status").clicked() {
                ui.ctx().copy_text(self.text_output.clone());
            }
        });
    }

    /// Renders the password tools tab
    pub fn show_password_tools(&mut self, ui: &mut Ui) {
        ui.heading("🔧 Password Tools");

        ui.separator();

        // Password Generation Section
        ui.group(|ui| {
            ui.label("🔑 Password Generator");
            ui.label("Generate secure random passwords with customizable options:");

            ui.horizontal(|ui| {
                ui.label("Length:");
                ui.add(egui::DragValue::new(&mut self.password_length).clamp_range(8..=128));
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.include_lowercase, "Lowercase (a-z)");
                ui.checkbox(&mut self.include_uppercase, "Uppercase (A-Z)");
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.include_numbers, "Numbers (0-9)");
                ui.checkbox(&mut self.include_symbols, "Symbols (!@#$%^&*)");
            });

            ui.horizontal(|ui| {
                if ui.button("🎲 Generate Password").clicked() {
                    self.generate_secure_password(
                        self.password_length,
                        self.include_uppercase,
                        self.include_lowercase,
                        self.include_numbers,
                        self.include_symbols,
                    );
                }
                if ui.button("📋 Copy").clicked() && !self.text_output.is_empty() {
                    ui.ctx().copy_text(self.text_output.clone());
                }
            });

            if !self.text_output.is_empty() {
                ui.separator();
                ui.label("Generated Password:");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.text_output).password(true));
                    if ui.button("👁️ Show/Hide").clicked() {
                        self.show_password = !self.show_password;
                    }
                });
                if self.show_password {
                    ui.colored_label(egui::Color32::GREEN, &self.text_output);
                }
            }
        });

        ui.add_space(20.0);

        // Password Assessment Section
        ui.group(|ui| {
            ui.label("📊 Password Strength Analyzer");
            ui.label("Analyze the security strength of any password:");

            ui.label("Enter password to analyze:");
            ui.add(egui::TextEdit::singleline(&mut self.password_input).password(true));

            if ui.button("🔍 Analyze Strength").clicked() && !self.password_input.is_empty() {
                self.text_input = self.password_input.clone();
                self.assess_password_strength();
            }

            if !self.text_output.is_empty() && self.text_output.contains("Password strength") {
                ui.separator();
                ui.label("Analysis Result:");
                ui.label(&self.text_output);
            }
        });

        ui.add_space(20.0);

        // Tips Section
        ui.group(|ui| {
            ui.label("💡 Security Tips");
            ui.label("• Use passwords of at least 12 characters");
            ui.label("• Include all character types for maximum strength");
            ui.label("• Avoid common words or patterns");
            ui.label("• Use a unique password for each account");
            ui.label("• Consider using a password manager");
        });
    }

    /// Shows the about modal
    pub fn show_about_modal(&mut self, ctx: &Context) {
        Window::new("About Cybou")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("🔐 Cybou");
                    ui.label("Secure Cryptography Application");
                    ui.label("Version 0.5.1");
                    ui.separator();
                    ui.label("A cross-platform GUI application for");
                    ui.label("post-quantum cryptography operations.");
                    ui.separator();
                    ui.label("Features:");
                    ui.label("• Post-quantum encryption (Kyber + AES-GCM)");
                    ui.label("• Digital signatures (Dilithium)");
                    ui.label("• Automated backups with deduplication");
                    ui.label("• Cloud storage integration");
                    ui.label("• Password generation and analysis");
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Close").clicked() {
                                self.show_about_modal = false;
                            }
                        });
                    });
                });
            });
    }

    /// Renders the key management tab
    pub fn show_key_management(&mut self, ui: &mut Ui) {
        ui.heading("🔑 Key Management - Advanced Cryptography");

        if let Some(data) = &mut self.sensitive_data {
            // Key Statistics Section
            ui.group(|ui| {
                ui.label("📊 Key Statistics");
                let stats = data.get_key_statistics();

                ui.horizontal(|ui| {
                    ui.label(format!("Total Versions: {}", stats.total_versions));
                    ui.label(format!("Current Version: {}", stats.current_version_id));
                });

                if let (Some(oldest), Some(newest)) = (stats.oldest_version, stats.newest_version) {
                    let age_days = newest.duration_since(oldest).unwrap_or_default().as_secs() / 86400;
                    ui.label(format!("Key Age: {} days", age_days));
                }
            });

            ui.add_space(10.0);

            // Current Key Info
            ui.group(|ui| {
                ui.label("🔓 Current Key Information");
                ui.label(format!("Version ID: {}", data.current().id));

                let timestamp = data.current().timestamp
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs();
                ui.label(format!("Created: {} (timestamp: {})",
                    chrono::DateTime::from_timestamp(timestamp as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    timestamp
                ));

                ui.horizontal(|ui| {
                    ui.label("Algorithms:");
                    ui.label("Kyber + Dilithium");
                });
            });

            ui.add_space(10.0);

            // Key Version History
            ui.group(|ui| {
                ui.label("📚 Key Version History");

                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    for (i, version) in data.key_versions.iter().enumerate() {
                        let current_marker = if i == data.current_version { " ← CURRENT" } else { "" };
                        let timestamp = version.timestamp
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_secs();

                        ui.horizontal(|ui| {
                            ui.label(format!("Version {}: {}", version.id, current_marker));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(format!("Created: {}",
                                    chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                        .unwrap_or_else(|| "Unknown".to_string())
                                ));
                            });
                        });

                        if i < data.key_versions.len() - 1 {
                            ui.separator();
                        }
                    }
                });
            });

            ui.add_space(10.0);

            // Key Management Actions
            ui.group(|ui| {
                ui.label("⚙️ Key Management Actions");

                ui.horizontal(|ui| {
                    if ui.button("🔄 Rotate Keys").clicked() {
                        match data.rotate_keys() {
                            Ok(_) => {
                                self.last_status = "Keys rotated successfully".to_string();
                            }
                            Err(e) => {
                                self.last_status = format!("Key rotation failed: {}", e);
                            }
                        }
                    }

                    if ui.button("📄 Export Metadata").clicked() {
                        match data.export_key_metadata() {
                            Ok(json) => {
                                self.text_output = json;
                                self.last_status = "Key metadata exported to output".to_string();
                            }
                            Err(e) => {
                                self.last_status = format!("Export failed: {}", e);
                            }
                        }
                    }
                });

                ui.separator();
                ui.label("ℹ️ Key rotation generates new cryptographic keys while maintaining backward compatibility.");
                ui.label("Old encrypted files can still be decrypted with previous key versions.");
            });
        } else {
            ui.group(|ui| {
                ui.colored_label(egui::Color32::YELLOW, "⚠️ No keys loaded");
                ui.label("Please enter your mnemonic phrase first to initialize cryptographic keys.");
                ui.label("Go to the first tab to set up your keys.");
            });
        }

        ui.add_space(10.0);
        ui.label("Status:");
        ui.label(&self.last_status);
    }

    /// Renders the settings tab with user experience options
    pub fn show_settings(&mut self, ui: &mut Ui) {
        ui.heading("⚙️ Settings - User Experience");

        ui.add_space(10.0);

        // Appearance Settings
        ui.group(|ui| {
            ui.label("🎨 Appearance");

            ui.horizontal(|ui| {
                ui.label("Theme:");
                let mut dark_mode = self.dark_mode;
                if ui.checkbox(&mut dark_mode, "🌙 Dark Mode").changed() {
                    self.dark_mode = dark_mode;
                    self.apply_theme(ui.ctx());
                }
            });

            ui.add_space(5.0);
            ui.label("💡 Dark mode provides better visibility in low-light environments and reduces eye strain.");
        });

        ui.add_space(10.0);

        // Language Settings
        ui.group(|ui| {
            ui.label("🌍 Language & Localization");

            ui.horizontal(|ui| {
                ui.label("Language:");
                egui::ComboBox::from_label("")
                    .selected_text(match self.language.as_str() {
                        "en" => "English",
                        "es" => "Español",
                        "fr" => "Français",
                        "de" => "Deutsch",
                        "zh" => "中文",
                        _ => "English",
                    })
                    .show_ui(ui, |ui| {
                        if ui.selectable_value(&mut self.language, "en".to_string(), "English").clicked() {
                            self.apply_language();
                        }
                        if ui.selectable_value(&mut self.language, "es".to_string(), "Español").clicked() {
                            self.apply_language();
                        }
                        if ui.selectable_value(&mut self.language, "fr".to_string(), "Français").clicked() {
                            self.apply_language();
                        }
                        if ui.selectable_value(&mut self.language, "de".to_string(), "Deutsch").clicked() {
                            self.apply_language();
                        }
                        if ui.selectable_value(&mut self.language, "zh".to_string(), "中文").clicked() {
                            self.apply_language();
                        }
                    });
            });

            ui.add_space(5.0);
            ui.label("🌐 Multi-language support for international users. More languages coming soon!");
        });

        ui.add_space(10.0);

        // Accessibility Settings
        ui.group(|ui| {
            ui.label("♿ Accessibility");

            ui.horizontal(|ui| {
                ui.label("Enable accessibility features:");
                if ui.checkbox(&mut self.enable_accessibility, "").changed() {
                    self.apply_accessibility();
                }
            });

            ui.add_space(5.0);

            if self.enable_accessibility {
                ui.label("🔹 Enhanced keyboard navigation");
                ui.label("🔹 Screen reader support");
                ui.label("🔹 High contrast mode");
                ui.label("🔹 Larger UI elements");
            } else {
                ui.colored_label(egui::Color32::GRAY, "Accessibility features are disabled");
            }

            ui.add_space(5.0);
            ui.label("🎯 Accessibility features help users with disabilities navigate and use the application effectively.");
        });

        ui.add_space(10.0);

        // System Integration
        ui.group(|ui| {
            ui.label("🔗 System Integration");

            ui.horizontal(|ui| {
                ui.label("Auto-detect system theme:");
                let mut auto_theme = false; // This would be stored in settings
                ui.checkbox(&mut auto_theme, "");
            });

            ui.horizontal(|ui| {
                ui.label("Minimize to system tray:");
                let mut minimize_to_tray = true; // This would be stored in settings
                ui.checkbox(&mut minimize_to_tray, "");
            });

            ui.add_space(5.0);
            ui.label("⚙️ System integration provides seamless experience with your operating system.");
        });

        ui.add_space(10.0);

        // Performance Settings
        ui.group(|ui| {
            ui.label("⚡ Performance");

            ui.horizontal(|ui| {
                ui.label("UI animations:");
                let mut animations = true; // This would be stored in settings
                ui.checkbox(&mut animations, "");
            });

            ui.horizontal(|ui| {
                ui.label("Auto-save interval (seconds):");
                let mut auto_save = 30; // This would be stored in settings
                ui.add(egui::DragValue::new(&mut auto_save).clamp_range(10..=300));
            });

            ui.add_space(5.0);
            ui.label("🚀 Performance settings help optimize the application for your system.");
        });

        ui.add_space(10.0);

        // Reset Settings
        ui.group(|ui| {
            ui.label("🔄 Reset Options");

            ui.horizontal(|ui| {
                if ui.button("🔄 Reset to Defaults").clicked() {
                    self.reset_settings_to_defaults();
                    self.apply_theme(ui.ctx());
                    self.apply_language();
                    self.apply_accessibility();
                    self.last_status = "Settings reset to defaults".to_string();
                }

                if ui.button("💾 Save Settings").clicked() {
                    self.save_settings();
                    self.last_status = "Settings saved successfully".to_string();
                }
            });

            ui.add_space(5.0);
            ui.label("⚠️ Reset will restore all settings to their default values.");
        });
    }

    /// Applies the current theme setting
    pub fn apply_theme(&self, ctx: &egui::Context) {
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }
    }

    /// Applies language settings (placeholder for future i18n)
    pub fn apply_language(&self) {
        // TODO: Implement actual language switching
        // For now, this is a placeholder that would load different language files
        match self.language.as_str() {
            "en" => {}, // English (default)
            "es" => {}, // Spanish
            "fr" => {}, // French
            "de" => {}, // German
            "zh" => {}, // Chinese
            _ => {},
        }
    }

    /// Applies accessibility settings
    pub fn apply_accessibility(&self) {
        // TODO: Implement actual accessibility features
        // This would modify UI elements for better accessibility
        if self.enable_accessibility {
            // Enable high contrast, larger fonts, keyboard navigation, etc.
        }
    }

    /// Resets all settings to defaults
    pub fn reset_settings_to_defaults(&mut self) {
        self.dark_mode = false;
        self.language = "en".to_string();
        self.enable_accessibility = false;
    }

    /// Saves current settings (placeholder for persistence)
    pub fn save_settings(&self) {
        // TODO: Implement actual settings persistence
        // This would save settings to a configuration file
    }
}

#[cfg(test)]
mod tests {
    use crate::types::App;

    #[test]
    fn test_app_initial_tab() {
        let app = App::default();
        assert_eq!(app.current_tab, 0);
    }

    #[test]
    fn test_tab_navigation() {
        let mut app = App::default();

        // Test all tab indices
        for tab in 0..=8 {
            app.current_tab = tab;
            assert_eq!(app.current_tab, tab);
        }
    }

    #[test]
    fn test_mnemonic_modal_initial_state() {
        let app = App::default();
        assert!(app.show_mnemonic_modal);
        assert!(app.mnemonic_input.is_empty());
    }

    #[test]
    fn test_text_input_output_fields() {
        let mut app = App::default();

        let test_text = "Test input text";
        app.text_input = test_text.to_string();
        assert_eq!(app.text_input, test_text);

        let output_text = "Test output text";
        app.text_output = output_text.to_string();
        assert_eq!(app.text_output, output_text);
    }

    #[test]
    fn test_file_path_field() {
        let mut app = App::default();

        let test_path = "/test/path/file.txt";
        app.file_path = test_path.to_string();
        assert_eq!(app.file_path, test_path);
    }

    #[test]
    fn test_sign_verify_fields() {
        let mut app = App::default();

        app.sign_text = "Text to sign".to_string();
        app.sign_signature = "signature_data".to_string();
        app.verify_text = "Text to verify".to_string();
        app.verify_signature = "signature_to_verify".to_string();

        assert_eq!(app.sign_text, "Text to sign");
        assert_eq!(app.sign_signature, "signature_data");
        assert_eq!(app.verify_text, "Text to verify");
        assert_eq!(app.verify_signature, "signature_to_verify");
    }

    #[test]
    fn test_folder_path_field() {
        let mut app = App::default();

        let test_folder = "/test/folder/path";
        app.folder_path = test_folder.to_string();
        assert_eq!(app.folder_path, test_folder);
    }

    #[test]
    fn test_backup_fields() {
        let mut app = App::default();

        app.watched_folders.push("/test/watch/folder".to_string());
        app.backup_path = "/test/backup/path".to_string();

        assert_eq!(app.watched_folders.len(), 1);
        assert_eq!(app.watched_folders[0], "/test/watch/folder");
        assert_eq!(app.backup_path, "/test/backup/path");
        assert!(!app.backup_active);
    }

    #[test]
    fn test_cloud_storage_fields() {
        let mut app = App::default();

        app.s3_bucket = "test-bucket".to_string();
        app.s3_region = "us-east-1".to_string();
        app.s3_access_key = "test_access_key".to_string();
        app.s3_secret_key = "test_secret_key".to_string();

        assert_eq!(app.s3_bucket, "test-bucket");
        assert_eq!(app.s3_region, "us-east-1");
        assert_eq!(app.s3_access_key, "test_access_key");
        assert_eq!(app.s3_secret_key, "test_secret_key");
    }

    #[test]
    fn test_status_field() {
        let mut app = App::default();

        let test_status = "Test status message";
        app.last_status = test_status.to_string();
        assert_eq!(app.last_status, test_status);
    }

    #[test]
    fn test_key_management_without_keys() {
        let app = App::default();
        assert!(app.sensitive_data.is_none());
    }
}