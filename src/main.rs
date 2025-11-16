//! Cybou - Secure Cryptography Application
//!
//! A cross-platform GUI application for post-quantum cryptography operations
//! including encryption, digital signatures, key management, and cloud storage.

mod types;
mod crypto;
mod ui;
mod backup;
mod cloud;

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
            menu.append(&MenuItem::new("Show Window", true, None)).unwrap();
            menu.append(&MenuItem::new("Quit", true, None)).unwrap();
            self.tray_icon = Some(TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_icon(icon)
                .with_tooltip("Cybou - Secure Crypto App")
                .build()
                .unwrap());
        }

        // Show mnemonic modal or main UI
        if self.show_mnemonic_modal {
            self.show_mnemonic_modal(ctx);
        } else {
            self.show_main_ui(ctx);
        }
    }
}
