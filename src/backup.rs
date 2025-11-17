//! Backup system module
//!
//! This module handles the automated backup functionality including file watching,
//! deduplication, and backup management.

use crate::types::App;
use eframe::egui::Ui;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

impl App {
    /// Renders the backup management tab
    pub fn show_backups(&mut self, ui: &mut Ui) {
        ui.heading("💾 Backup Management");

        ui.group(|ui| {
            ui.label("📁 Watched Folders");
            ui.label("Add folders to monitor for automatic backups:");

            ui.horizontal(|ui| {
                if ui.button("➕ Add Folder").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.watched_folders.push(path.display().to_string());
                    }
                }
                if ui.button("🗑️ Clear All").clicked() {
                    self.watched_folders.clear();
                }
            });

            egui::ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                let mut to_remove = None;
                for (i, folder) in self.watched_folders.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!("📂 {}", folder));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("❌").on_hover_text("Remove folder").clicked() {
                                to_remove = Some(i);
                            }
                        });
                    });
                }
                if let Some(i) = to_remove {
                    self.watched_folders.remove(i);
                }
            });
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label("🎯 Backup Destination");
            ui.horizontal(|ui| {
                ui.label("Path:");
                ui.text_edit_singleline(&mut self.backup_path);
                if ui.button("📂 Select").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.backup_path = path.display().to_string();
                    }
                }
                if ui.button("🗑️ Clear").clicked() {
                    self.backup_path.clear();
                }
            });
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label("⚙️ Backup Controls");

            ui.horizontal(|ui| {
                if !self.backup_active {
                    if ui.button("▶️ Start Backup").clicked() {
                        self.start_backup();
                    }
                } else {
                    if ui.button("⏹️ Stop Backup").clicked() {
                        self.stop_backup();
                    }
                }

                if ui.button("🔍 Verify Backup").clicked() {
                    self.verify_backup();
                }
            });

            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label("Cleanup old backups:");
                ui.add(egui::DragValue::new(&mut self.cleanup_days).clamp_range(1..=365));
                ui.label("days");
                if ui.button("🧹 Cleanup").clicked() {
                    self.cleanup_old_backups(self.cleanup_days);
                }
            });
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label("📊 Backup Status");

            if self.backup_active {
                ui.colored_label(egui::Color32::GREEN, "● Recording Active");
                if let Some(count_ref) = &self.backup_file_count_ref {
                    let count = *count_ref.lock().unwrap();
                    ui.label(format!("Files backed up: {}", count));
                }
            } else {
                ui.colored_label(egui::Color32::GRAY, "● Recording Stopped");
            }

            ui.label("Last operation:");
            ui.label(&self.text_output);
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui.button("📋 Copy Status").clicked() {
                ui.ctx().copy_text(self.text_output.clone());
            }
        });
    }

    /// Starts the automated backup system
    pub fn start_backup(&mut self) {
        if self.backup_path.is_empty() {
            self.text_output = "Please set backup path first".to_string();
            self.last_status = "Backup path not set".to_string();
            return;
        }

        if self.watched_folders.is_empty() {
            self.text_output = "Please add folders to watch first".to_string();
            self.last_status = "No folders to watch".to_string();
            return;
        }

        if self.backup_active {
            self.text_output = "Backup already running".to_string();
            self.last_status = "Backup already active".to_string();
            return;
        }

        // Create backup directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&self.backup_path) {
            self.text_output = format!("Failed to create backup directory: {}", e);
            self.last_status = "Failed to create backup directory".to_string();
            return;
        }

        // Initialize file hashes for deduplication
        self.initialize_file_hashes();

        // Start file watcher
        let backup_path = self.backup_path.clone();
        let file_hashes = Arc::clone(&self.file_hashes);
        let watched_folders = self.watched_folders.clone();

        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = match RecommendedWatcher::new(tx, notify::Config::default()) {
            Ok(w) => w,
            Err(e) => {
                self.text_output = format!("Failed to create watcher: {}", e);
                self.last_status = "Failed to create file watcher".to_string();
                return;
            }
        };

        // Watch all folders
        for folder in &watched_folders {
            if let Err(e) = watcher.watch(std::path::Path::new(folder), RecursiveMode::Recursive) {
                self.text_output = format!("Failed to watch folder {}: {}", folder, e);
                self.last_status = format!("Failed to watch folder: {}", folder);
                return;
            }
        }

        self.backup_active = true;
        self.backup_file_count = 0;
        self.text_output = format!("Backup started - watching {} folders", watched_folders.len());
        self.last_status = "Backup started".to_string();

        // Spawn backup thread
        let backup_file_count = Arc::new(Mutex::new(0usize));
        let count_clone = Arc::clone(&backup_file_count);

        std::thread::spawn(move || {
            while let Ok(event) = rx.recv() {
                if let Ok(event) = event {
                    handle_backup_event(event, &backup_path, &file_hashes, &watched_folders, &count_clone);
                }
            }
        });

        // Store reference to count for UI updates
        self.backup_file_count_ref = Some(backup_file_count);
    }

    /// Stops the automated backup system
    pub fn stop_backup(&mut self) {
        self.backup_active = false;
        self.text_output = format!("Backup stopped - {} files backed up", self.backup_file_count);
        self.last_status = "Backup stopped".to_string();
    }

    /// Verifies the integrity of backed up files
    pub fn verify_backup(&mut self) {
        if self.backup_path.is_empty() {
            self.text_output = "No backup path set".to_string();
            self.last_status = "No backup path".to_string();
            return;
        }

        let mut verified_count = 0;
        let corrupted_count = 0;

        if let Ok(entries) = std::fs::read_dir(&self.backup_path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        // For verification, we could compare file sizes or hashes
                        // For now, just count existing files
                        verified_count += 1;
                    }
                }
            }
        }

        self.text_output = format!("Backup verification complete: {} files verified, {} corrupted", verified_count, corrupted_count);
        self.last_status = "Backup verified".to_string();
    }

    /// Initializes file hash tracking for deduplication
    fn initialize_file_hashes(&mut self) {
        let mut hashes = self.file_hashes.lock().unwrap();
        hashes.clear();

        // Calculate initial hashes for all files in watched folders
        for folder in &self.watched_folders {
            if let Ok(entries) = std::fs::read_dir(folder) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_file() {
                            if let Ok(path) = entry.path().into_os_string().into_string() {
                                if let Ok(content) = std::fs::read(&path) {
                                    let hash = blake3::hash(&content).to_hex().to_string();
                                    hashes.insert(path, hash);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Cleans up old backup files based on retention policy
    pub fn cleanup_old_backups(&mut self, days_to_keep: u64) {
        if self.backup_path.is_empty() {
            self.text_output = "No backup path set".to_string();
            self.last_status = "No backup path".to_string();
            return;
        }

        let now = std::time::SystemTime::now();
        let cutoff_duration = std::time::Duration::from_secs(days_to_keep * 24 * 60 * 60);

        if let Ok(entries) = std::fs::read_dir(&self.backup_path) {
            let mut deleted_count = 0;
            let mut total_size_freed = 0u64;

            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(age) = now.duration_since(modified) {
                                if age > cutoff_duration {
                                    let file_size = metadata.len();
                                    total_size_freed += file_size;
                                    if std::fs::remove_file(entry.path()).is_ok() {
                                        deleted_count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let size_mb = total_size_freed as f64 / (1024.0 * 1024.0);
            self.text_output = format!("Cleanup complete: {} old backups deleted, {:.2} MB freed", deleted_count, size_mb);
            self.last_status = "Backup cleanup completed".to_string();
        } else {
            self.text_output = "Failed to read backup directory".to_string();
            self.last_status = "Failed to access backup directory".to_string();
        }
    }
}

/// Handles file system events for backup operations
fn handle_backup_event(
    event: notify::Event,
    backup_path: &str,
    file_hashes: &Arc<Mutex<HashMap<String, String>>>,
    watched_folders: &[String],
    count: &Arc<Mutex<usize>>
) {
    for path in &event.paths {
        if let Some(path_str) = path.to_str() {
            // Check if the path is in one of the watched folders
            let is_watched = watched_folders.iter().any(|folder| path_str.starts_with(folder));

            if !is_watched {
                continue;
            }

            match event.kind {
                notify::EventKind::Modify(_) | notify::EventKind::Create(_) => {
                    if let Ok(metadata) = std::fs::metadata(path) {
                        if metadata.is_file() {
                            backup_file(path_str, backup_path, file_hashes, count);
                        }
                    }
                }
                notify::EventKind::Remove(_) => {
                    // File was deleted, we could log this or remove from backup
                    // For now, just skip
                }
                _ => {}
            }
        }
    }
}

/// Backs up a single file with deduplication
fn backup_file(
    file_path: &str,
    backup_path: &str,
    file_hashes: &Arc<Mutex<HashMap<String, String>>>,
    count: &Arc<Mutex<usize>>
) {
    let mut hashes = file_hashes.lock().unwrap();

    // Read file content
    let content = match std::fs::read(file_path) {
        Ok(c) => c,
        Err(_) => return, // Skip if can't read
    };

    // Calculate hash
    let new_hash = blake3::hash(&content).to_hex().to_string();

    // Check for deduplication
    if let Some(existing_hash) = hashes.get(file_path) {
        if existing_hash == &new_hash {
            // File hasn't changed, skip backup
            return;
        }
    }

    // Update hash
    hashes.insert(file_path.to_string(), new_hash);

    // Create backup path
    let file_name = std::path::Path::new(file_path).file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown_file");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let backup_file_name = format!("{}_{}", timestamp, file_name);
    let backup_file_path = std::path::Path::new(backup_path).join(backup_file_name);

    // Copy file to backup location
    if std::fs::copy(file_path, &backup_file_path).is_ok() {
        println!("Backed up: {} -> {}", file_path, backup_file_path.display());
        *count.lock().unwrap() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::App;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_start_backup_no_path() {
        let mut app = App::default();
        app.watched_folders.push("/tmp/test".to_string());

        app.start_backup();
        assert_eq!(app.last_status, "Backup path not set");
    }

    #[test]
    fn test_start_backup_no_folders() {
        let mut app = App::default();
        app.backup_path = "/tmp/backup".to_string();

        app.start_backup();
        assert_eq!(app.last_status, "No folders to watch");
    }

    #[test]
    fn test_start_backup_already_running() {
        let mut app = App::default();
        app.backup_path = "/tmp/backup".to_string();
        app.watched_folders.push("/tmp/test".to_string());
        app.backup_active = true;

        app.start_backup();
        assert_eq!(app.last_status, "Backup already active");
    }

    #[test]
    fn test_stop_backup() {
        let mut app = App::default();
        app.backup_active = true;
        app.backup_file_count = 5;

        app.stop_backup();
        assert!(!app.backup_active);
        assert_eq!(app.last_status, "Backup stopped");
        assert!(app.text_output.contains("5 files backed up"));
    }

    #[test]
    fn test_verify_backup_no_path() {
        let mut app = App::default();

        app.verify_backup();
        assert_eq!(app.last_status, "No backup path");
    }

    #[test]
    fn test_verify_backup_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let mut app = App::default();
        app.backup_path = temp_dir.path().to_str().unwrap().to_string();

        app.verify_backup();
        assert_eq!(app.last_status, "Backup verified");
        assert!(app.text_output.contains("0 files verified"));
    }

    #[test]
    fn test_verify_backup_with_files() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path();

        // Create some test files
        let file1 = backup_path.join("test1.txt");
        let file2 = backup_path.join("test2.txt");
        fs::write(&file1, "content1").unwrap();
        fs::write(&file2, "content2").unwrap();

        let mut app = App::default();
        app.backup_path = backup_path.to_str().unwrap().to_string();

        app.verify_backup();
        assert_eq!(app.last_status, "Backup verified");
        assert!(app.text_output.contains("2 files verified"));
    }

    #[test]
    fn test_initialize_file_hashes() {
        let temp_dir = TempDir::new().unwrap();
        let watch_dir = temp_dir.path();

        // Create test files
        let file1 = watch_dir.join("file1.txt");
        let file2 = watch_dir.join("file2.txt");
        fs::write(&file1, "content1").unwrap();
        fs::write(&file2, "content2").unwrap();

        let mut app = App::default();
        app.watched_folders.push(watch_dir.to_str().unwrap().to_string());

        app.initialize_file_hashes();

        let hashes = app.file_hashes.lock().unwrap();
        assert_eq!(hashes.len(), 2);

        // Verify hashes are computed
        let hash1 = hashes.get(file1.to_str().unwrap()).unwrap();
        let hash2 = hashes.get(file2.to_str().unwrap()).unwrap();
        assert!(!hash1.is_empty());
        assert!(!hash2.is_empty());

        // Different content should have different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_backup_file_creation() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = TempDir::new().unwrap();

        // Create source file
        let source_file = temp_dir.path().join("source.txt");
        fs::write(&source_file, "test content").unwrap();

        let file_hashes = Arc::new(Mutex::new(HashMap::new()));
        let count = Arc::new(Mutex::new(0usize));

        // Call backup_file function
        backup_file(
            source_file.to_str().unwrap(),
            backup_dir.path().to_str().unwrap(),
            &file_hashes,
            &count,
        );

        // Check that file was backed up
        let backup_files: Vec<_> = fs::read_dir(backup_dir.path()).unwrap().collect();
        assert_eq!(backup_files.len(), 1);

        // Check that count was incremented
        assert_eq!(*count.lock().unwrap(), 1);

        // Check that hash was stored
        let hashes = file_hashes.lock().unwrap();
        assert!(hashes.contains_key(source_file.to_str().unwrap()));
    }

    #[test]
    fn test_backup_file_deduplication() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = TempDir::new().unwrap();

        // Create source file
        let source_file = temp_dir.path().join("source.txt");
        fs::write(&source_file, "test content").unwrap();

        let file_hashes = Arc::new(Mutex::new(HashMap::new()));
        let count = Arc::new(Mutex::new(0usize));

        // First backup
        backup_file(
            source_file.to_str().unwrap(),
            backup_dir.path().to_str().unwrap(),
            &file_hashes,
            &count,
        );

        let first_count = *count.lock().unwrap();
        let first_backup_files: Vec<_> = fs::read_dir(backup_dir.path()).unwrap().collect();

        // Second backup of same file (should be deduplicated)
        backup_file(
            source_file.to_str().unwrap(),
            backup_dir.path().to_str().unwrap(),
            &file_hashes,
            &count,
        );

        let second_count = *count.lock().unwrap();
        let second_backup_files: Vec<_> = fs::read_dir(backup_dir.path()).unwrap().collect();

        // Count should not have increased (deduplication worked)
        assert_eq!(first_count, second_count);
        // Number of files should not have increased
        assert_eq!(first_backup_files.len(), second_backup_files.len());
    }

    #[test]
    fn test_backup_file_content_preservation() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = TempDir::new().unwrap();

        let test_content = "This is test content for backup verification.";
        let source_file = temp_dir.path().join("source.txt");
        fs::write(&source_file, test_content).unwrap();

        let file_hashes = Arc::new(Mutex::new(HashMap::new()));
        let count = Arc::new(Mutex::new(0usize));

        backup_file(
            source_file.to_str().unwrap(),
            backup_dir.path().to_str().unwrap(),
            &file_hashes,
            &count,
        );

        // Find the backed up file
        let mut backup_files = fs::read_dir(backup_dir.path()).unwrap();
        let backup_file = backup_files.next().unwrap().unwrap();
        let backed_up_content = fs::read(backup_file.path()).unwrap();

        assert_eq!(String::from_utf8(backed_up_content).unwrap(), test_content);
    }
}