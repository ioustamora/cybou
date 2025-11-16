fn main() {
    println!("cargo:rerun-if-changed=ui/");
    // Compile all Slint UI files
    slint_build::compile("ui/main_dashboard.slint").unwrap();
    slint_build::compile("ui/text_encryption.slint").unwrap();
    slint_build::compile("ui/file_encryption.slint").unwrap();
    slint_build::compile("ui/digital_signatures.slint").unwrap();
    slint_build::compile("ui/password_tools.slint").unwrap();
    slint_build::compile("ui/backup_management.slint").unwrap();
    slint_build::compile("ui/cloud_storage.slint").unwrap();
    slint_build::compile("ui/key_management.slint").unwrap();
    slint_build::compile("ui/settings.slint").unwrap();
    slint_build::compile("ui/folder_encryption.slint").unwrap();
}