//! Cybou - Secure Cryptography Application
//!
//! A cross-platform GUI application for post-quantum cryptography operations
//! including encryption, digital signatures, key management, and cloud storage.

mod types;
mod crypto;
mod ui;
mod backup;
mod cloud;
mod windows;

use eframe::egui::Context;
use tray_icon::{TrayIconBuilder, Icon, menu::Menu, menu::MenuItem, TrayIconEvent};

/// Main application entry point
fn main() -> Result<(), eframe::Error> {
    // Initialize system tray
    std::thread::spawn(|| {
        while let Ok(event) = TrayIconEvent::receiver().recv() {
            match event {
                TrayIconEvent::Click { id, .. } => {
                    if id == "Quit" {
                        std::process::exit(0);
                    }
                }
                _ => {}
            }
        }
    });

    // Load application icon
    let icon_data = if let Ok(img) = image::open("cybou.ico") {
        let rgba_img = img.to_rgba8();
        let width = rgba_img.width();
        let height = rgba_img.height();
        let rgba = rgba_img.into_raw();
        Some(std::sync::Arc::new(eframe::egui::IconData {
            rgba,
            width,
            height,
        }))
    } else {
        None
    };

    // Configure native options
    let mut options = eframe::NativeOptions::default();
    if let Some(icon) = icon_data {
        options.viewport.icon = Some(icon);
    }

    // Run the application
    eframe::run_native(
        "Cybou - Secure Crypto App",
        options,
        Box::new(|_cc| Box::new(types::App::default())),
    )
}

// Implement eframe::App for the App struct
impl eframe::App for types::App {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Initialize system tray icon if not already done
        if self.tray_icon.is_none() {
            let icon = Icon::from_rgba(vec![0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255, 0, 255, 0, 255], 2, 2).unwrap();
            let menu = Menu::new();
            menu.append(&MenuItem::new("Show Dashboard", true, None)).unwrap();
            menu.append(&MenuItem::new("Text Encryption", true, None)).unwrap();
            menu.append(&MenuItem::new("File Encryption", true, None)).unwrap();
            menu.append(&MenuItem::new("Digital Signatures", true, None)).unwrap();
            menu.append(&MenuItem::new("Password Tools", true, None)).unwrap();
            menu.append(&MenuItem::new("Backup Management", true, None)).unwrap();
            menu.append(&MenuItem::new("Cloud Storage", true, None)).unwrap();
            menu.append(&MenuItem::new("Key Management", true, None)).unwrap();
            menu.append(&MenuItem::new("Settings", true, None)).unwrap();
            menu.append(&MenuItem::new("Quit", true, None)).unwrap();
            self.tray_icon = Some(TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_icon(icon)
                .with_tooltip("Cybou - Secure Crypto App")
                .build()
                .unwrap());
        }

        // Handle tray icon events
        if let Ok(event) = TrayIconEvent::receiver().try_recv() {
            match event {
                TrayIconEvent::Click { id, .. } => {
                    if id == "Quit" {
                        std::process::exit(0);
                    } else if id == "Show Dashboard" {
                        self.open_window(crate::windows::WindowType::Main);
                    } else if id == "Text Encryption" {
                        self.open_window(crate::windows::WindowType::TextEncryption);
                    } else if id == "File Encryption" {
                        self.open_window(crate::windows::WindowType::FileEncryption);
                    } else if id == "Digital Signatures" {
                        self.open_window(crate::windows::WindowType::DigitalSignatures);
                    } else if id == "Password Tools" {
                        self.open_window(crate::windows::WindowType::PasswordTools);
                    } else if id == "Backup Management" {
                        self.open_window(crate::windows::WindowType::BackupManagement);
                    } else if id == "Cloud Storage" {
                        self.open_window(crate::windows::WindowType::CloudStorage);
                    } else if id == "Key Management" {
                        self.open_window(crate::windows::WindowType::KeyManagement);
                    } else if id == "Settings" {
                        self.open_window(crate::windows::WindowType::Settings);
                    }
                }
                _ => {}
            }
        }

        // Show mnemonic modal or main windows
        if self.show_mnemonic_modal {
            self.show_mnemonic_modal(ctx);
        } else {
            self.render_windows(ctx);
        }
    }
}
