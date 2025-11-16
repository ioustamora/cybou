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

use slint::ComponentHandle;
use tray_icon::{TrayIconBuilder, Icon, menu::Menu, menu::MenuItem, TrayIconEvent};

/// Main application entry point
fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Create the main application instance
    let app = types::App::default();

    // Initialize system tray icon
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

    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .with_tooltip("Cybou - Secure Crypto App")
        .build()
        .unwrap();

    // Run the application
    app.run()?;

    Ok(())
}
