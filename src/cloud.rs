//! Cloud storage module
//!
//! This module handles cloud storage operations including AWS S3 integration
//! and multi-provider cloud storage support.

use crate::types::App;
use eframe::egui::Ui;

impl App {
    /// Renders the cloud storage configuration tab
    pub fn show_cloud_storage(&mut self, ui: &mut Ui) {
        ui.label("Cloud Storage Configuration");

        ui.horizontal(|ui| {
            ui.label("Provider:");
            ui.radio_value(&mut self.cloud_provider, crate::types::CloudProvider::None, "None");
            ui.radio_value(&mut self.cloud_provider, crate::types::CloudProvider::AWS, "AWS S3");
            ui.radio_value(&mut self.cloud_provider, crate::types::CloudProvider::GCP, "Google Cloud");
            ui.radio_value(&mut self.cloud_provider, crate::types::CloudProvider::Azure, "Azure");
        });

        match self.cloud_provider {
            crate::types::CloudProvider::AWS => {
                ui.label("AWS S3 Configuration:");
                ui.horizontal(|ui| {
                    ui.label("Bucket:");
                    ui.text_edit_singleline(&mut self.s3_bucket);
                });
                ui.horizontal(|ui| {
                    ui.label("Region:");
                    ui.text_edit_singleline(&mut self.s3_region);
                });
                ui.horizontal(|ui| {
                    ui.label("Access Key:");
                    ui.text_edit_singleline(&mut self.s3_access_key);
                });
                ui.horizontal(|ui| {
                    ui.label("Secret Key:");
                    ui.add(egui::TextEdit::singleline(&mut self.s3_secret_key).password(true));
                });

                if ui.button("Connect to S3").clicked() {
                    self.connect_s3();
                }

                ui.label("File to upload:");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.file_path);
                    if ui.button("Select File").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.file_path = path.display().to_string();
                        }
                    }
                    if ui.button("Upload File").clicked() {
                        self.upload_to_s3();
                    }
                });

                ui.label("S3 Key for download:");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.file_path);
                    if ui.button("Download File").clicked() {
                        self.download_from_s3();
                    }
                });
            }
            crate::types::CloudProvider::GCP => {
                ui.label("Google Cloud Storage - Coming Soon");
            }
            crate::types::CloudProvider::Azure => {
                ui.label("Azure Blob Storage - Coming Soon");
            }
            crate::types::CloudProvider::None => {
                ui.label("Select a cloud provider above to configure cloud storage.");
            }
        }

        ui.label("Status:");
        ui.label(&self.text_output);
    }

    /// Connects to AWS S3 using provided credentials
    pub fn connect_s3(&mut self) {
        if self.s3_bucket.is_empty() || self.s3_region.is_empty() || self.s3_access_key.is_empty() || self.s3_secret_key.is_empty() {
            self.text_output = "Please fill in all S3 configuration fields".to_string();
            self.last_status = "S3 configuration incomplete".to_string();
            return;
        }

        let access_key = self.s3_access_key.clone();
        let secret_key = self.s3_secret_key.clone();
        let region = self.s3_region.clone();
        let bucket = self.s3_bucket.clone();

        // Create S3 client in a separate thread since it's async
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = aws_config::defaults(aws_config::BehaviorVersion::v2024_03_28())
                    .region(aws_types::region::Region::new(region))
                    .credentials_provider(
                        aws_sdk_s3::config::Credentials::new(access_key, secret_key, None, None, "cybou")
                    )
                    .load()
                    .await;

                let client = aws_sdk_s3::Client::new(&config);
                // Test connection by listing objects
                match client.list_objects_v2().bucket(&bucket).send().await {
                    Ok(_) => println!("S3 connection successful"),
                    Err(e) => println!("S3 connection failed: {}", e),
                }
            });
        });

        self.text_output = "Connecting to S3...".to_string();
        self.last_status = "Connecting to S3".to_string();
    }

    /// Uploads a file to AWS S3
    pub fn upload_to_s3(&mut self) {
        if self.s3_bucket.is_empty() || self.s3_region.is_empty() || self.s3_access_key.is_empty() || self.s3_secret_key.is_empty() {
            self.text_output = "Please configure S3 first".to_string();
            self.last_status = "S3 not configured".to_string();
            return;
        }

        if self.file_path.is_empty() {
            self.text_output = "Please select a file to upload".to_string();
            self.last_status = "No file selected".to_string();
            return;
        }

        let access_key = self.s3_access_key.clone();
        let secret_key = self.s3_secret_key.clone();
        let region = self.s3_region.clone();
        let bucket = self.s3_bucket.clone();
        let file_path = self.file_path.clone();

        self.text_output = "Uploading to S3...".to_string();
        self.last_status = "Uploading to S3".to_string();

        // Upload in a separate thread
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = aws_config::defaults(aws_config::BehaviorVersion::v2024_03_28())
                    .region(aws_types::region::Region::new(region))
                    .credentials_provider(
                        aws_sdk_s3::config::Credentials::new(access_key, secret_key, None, None, "cybou")
                    )
                    .load()
                    .await;

                let client = aws_sdk_s3::Client::new(&config);

                // Read file content
                let file_content = match std::fs::read(&file_path) {
                    Ok(content) => content,
                    Err(e) => {
                        println!("Failed to read file: {}", e);
                        return;
                    }
                };

                let file_name = std::path::Path::new(&file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown_file");

                // Upload to S3
                match client.put_object()
                    .bucket(&bucket)
                    .key(file_name)
                    .body(file_content.into())
                    .send()
                    .await {
                    Ok(_) => println!("File uploaded successfully to S3"),
                    Err(e) => println!("Failed to upload to S3: {}", e),
                }
            });
        });
    }

    /// Downloads a file from AWS S3
    pub fn download_from_s3(&mut self) {
        if self.s3_bucket.is_empty() || self.s3_region.is_empty() || self.s3_access_key.is_empty() || self.s3_secret_key.is_empty() {
            self.text_output = "Please configure S3 first".to_string();
            self.last_status = "S3 not configured".to_string();
            return;
        }

        if self.file_path.is_empty() {
            self.text_output = "Please enter the S3 key to download".to_string();
            self.last_status = "No S3 key specified".to_string();
            return;
        }

        let access_key = self.s3_access_key.clone();
        let secret_key = self.s3_secret_key.clone();
        let region = self.s3_region.clone();
        let bucket = self.s3_bucket.clone();
        let key = self.file_path.clone();

        self.text_output = "Downloading from S3...".to_string();
        self.last_status = "Downloading from S3".to_string();

        // Download in a separate thread
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = aws_config::defaults(aws_config::BehaviorVersion::v2024_03_28())
                    .region(aws_types::region::Region::new(region))
                    .credentials_provider(
                        aws_sdk_s3::config::Credentials::new(access_key, secret_key, None, None, "cybou")
                    )
                    .load()
                    .await;

                let client = aws_sdk_s3::Client::new(&config);

                // Download from S3
                match client.get_object()
                    .bucket(&bucket)
                    .key(&key)
                    .send()
                    .await {
                    Ok(resp) => {
                        let data = resp.body.collect().await.unwrap().into_bytes();
                        let download_path = format!("{}_downloaded", key);
                        match std::fs::write(&download_path, data) {
                            Ok(_) => println!("File downloaded successfully from S3 to {}", download_path),
                            Err(e) => println!("Failed to save downloaded file: {}", e),
                        }
                    }
                    Err(e) => println!("Failed to download from S3: {}", e),
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{App, CloudProvider};

    #[test]
    fn test_connect_s3_missing_bucket() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.s3_region = "us-east-1".to_string();
        app.s3_access_key = "test_key".to_string();
        app.s3_secret_key = "test_secret".to_string();
        // bucket is empty

        app.connect_s3();
        assert_eq!(app.last_status, "S3 configuration incomplete");
    }

    #[test]
    fn test_connect_s3_missing_region() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.s3_bucket = "test-bucket".to_string();
        app.s3_access_key = "test_key".to_string();
        app.s3_secret_key = "test_secret".to_string();
        // region is empty

        app.connect_s3();
        assert_eq!(app.last_status, "S3 configuration incomplete");
    }

    #[test]
    fn test_connect_s3_missing_access_key() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.s3_bucket = "test-bucket".to_string();
        app.s3_region = "us-east-1".to_string();
        app.s3_secret_key = "test_secret".to_string();
        // access_key is empty

        app.connect_s3();
        assert_eq!(app.last_status, "S3 configuration incomplete");
    }

    #[test]
    fn test_connect_s3_missing_secret_key() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.s3_bucket = "test-bucket".to_string();
        app.s3_region = "us-east-1".to_string();
        app.s3_access_key = "test_key".to_string();
        // secret_key is empty

        app.connect_s3();
        assert_eq!(app.last_status, "S3 configuration incomplete");
    }

    #[test]
    fn test_upload_to_s3_missing_config() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.file_path = "/test/file.txt".to_string();

        app.upload_to_s3();
        assert_eq!(app.last_status, "S3 not configured");
    }

    #[test]
    fn test_upload_to_s3_missing_file() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.s3_bucket = "test-bucket".to_string();
        app.s3_region = "us-east-1".to_string();
        app.s3_access_key = "test_key".to_string();
        app.s3_secret_key = "test_secret".to_string();
        // file_path is empty

        app.upload_to_s3();
        assert_eq!(app.last_status, "No file selected");
    }

    #[test]
    fn test_download_from_s3_missing_config() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.file_path = "test-key".to_string();

        app.download_from_s3();
        assert_eq!(app.last_status, "S3 not configured");
    }

    #[test]
    fn test_download_from_s3_missing_key() {
        let mut app = App::default();
        app.cloud_provider = CloudProvider::AWS;
        app.s3_bucket = "test-bucket".to_string();
        app.s3_region = "us-east-1".to_string();
        app.s3_access_key = "test_key".to_string();
        app.s3_secret_key = "test_secret".to_string();
        // file_path is empty

        app.download_from_s3();
        assert_eq!(app.last_status, "No S3 key specified");
    }

    #[test]
    fn test_cloud_provider_config_validation() {
        let mut app = App::default();

        // Test None provider
        app.cloud_provider = CloudProvider::None;
        assert_eq!(app.cloud_provider, CloudProvider::None);

        // Test AWS provider
        app.cloud_provider = CloudProvider::AWS;
        assert_eq!(app.cloud_provider, CloudProvider::AWS);

        // Test GCP provider
        app.cloud_provider = CloudProvider::GCP;
        assert_eq!(app.cloud_provider, CloudProvider::GCP);

        // Test Azure provider
        app.cloud_provider = CloudProvider::Azure;
        assert_eq!(app.cloud_provider, CloudProvider::Azure);
    }
}