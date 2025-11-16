# Cybou - Secure Cryptography App

A cross-platform Rust GUI application for secure cryptography using post-quantum algorithms and mnemonic-based key derivation.

## Features

### 🔐 Core Security

- **Mnemonic-based Key Derivation**: Uses BIP39 standard for secure key generation from 12/24-word phrases
- **Post-Quantum Cryptography**: Implements NIST-recommended PQ algorithms
  - Kyber (ML-KEM) for key encapsulation and encryption
  - Dilithium (ML-DSA) for digital signatures
  - Falcon and SPHINCS+ additional signature algorithms
- **Hybrid Encryption**: Combines PQ key exchange with AES-GCM for data encryption
- **Key Rotation**: Automatic key rotation with version management and backward compatibility
- **Secure Memory**: Uses zeroize crate for secure memory wiping

### 🖥️ User Interface

- **Multi-Window Architecture**: Separate windows for different functions instead of tabs
- **Dashboard**: Main window with aggregated statistics and quick actions
- **System Tray Integration**: Enhanced tray menu for opening specific windows
- **Native GUI**: Built with eframe/egui for cross-platform compatibility
- **File Dialogs**: Native OS file/folder selection dialogs

### 📁 Cryptographic Operations

- **Text Encryption/Decryption**: Encrypt and decrypt text with base64 encoding
- **File Encryption/Decryption**: Secure file encryption with PQ + AES hybrid scheme
- **Folder Encryption**: Archive and encrypt entire directories
- **Digital Signatures**: Sign messages and verify signatures
- **Password Generation**: Generate secure random passwords with customizable complexity
- **Password Assessment**: Analyze password strength and security
- **Backup System**: Automated deduplicating backup with real-time file watching ✅
  - File system monitoring with change detection
  - Content-based deduplication using BLAKE3
  - Progress tracking and verification
  - Multi-folder support with configurable destinations
  - Automatic cleanup of old backups
- **Cloud Storage**: Encrypted cloud backups with AWS S3 integration ✅
  - Secure upload/download to AWS S3 buckets
  - Integrated with existing encryption framework
  - Multi-cloud provider support (AWS, GCP, Azure planned)
- **Key Management**: Advanced key lifecycle management
  - Key version tracking and rotation
  - Key metadata export/import
  - Key statistics and analytics

## Installation

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Windows/Linux/macOS

### Build from Source

```bash
git clone <repository-url>
cd cybou
cargo build --release
```

### Run

```bash
cargo run --release
```

## Usage

1. **First Launch**: Enter a valid 12 or 24-word BIP39 mnemonic phrase
2. **Key Derivation**: The app derives PQ keys and master encryption key from your mnemonic
3. **Operations**:
   - **Text Tab**: Encrypt/decrypt text messages
   - **File Tab**: Encrypt/decrypt files
   - **Sign/Verify Tab**: Create and verify digital signatures
   - **Folder Tab**: Encrypt entire folders
   - **Backups Tab**: Configure automated backup system
   - **Cloud Storage Tab**: Upload/download encrypted files to/from cloud storage
   - **Key Management Tab**: View key versions, rotate keys, and manage cryptographic security

## Security Notes

- **Mnemonic Security**: Your mnemonic phrase is the master key to all your data
- **Key Storage**: Keys are derived on-demand and securely wiped after use
- **PQ Algorithms**: Uses NIST-standard post-quantum cryptography resistant to quantum attacks
- **Hybrid Scheme**: Combines PQ security with proven symmetric encryption

## Dependencies

### Runtime Dependencies

- `eframe` / `egui`: GUI framework
- `bip39`: BIP39 mnemonic handling
- `pbkdf2`: Password-based key derivation
- `pqc_kyber`: Kyber post-quantum encryption
- `pqc_dilithium`: Dilithium post-quantum signatures
- `falcon-rust`: Falcon post-quantum signatures
- `pqcrypto-sphincsplus`: SPHINCS+ post-quantum signatures
- `aes-gcm`: AES-GCM symmetric encryption
- `base64`: Safe encoding
- `zeroize`: Secure memory wiping
- `rand`: Cryptographic randomness
- `rfd`: Native file dialogs
- `tar` / `flate2`: Archive compression
- `tray-icon`: System tray integration
- `notify`: File system monitoring
- `blake3`: Fast cryptographic hashing
- `aws-config` / `aws-sdk-s3`: AWS S3 cloud storage integration

## Architecture

The application follows a modular architecture for better maintainability and separation of concerns:

```text
src/
├── main.rs              # Application entry point and system tray integration
├── types.rs             # Core data structures and type definitions
├── crypto.rs            # Cryptographic operations and key management
├── ui.rs                # User interface components and rendering
├── backup.rs            # Automated backup system and file monitoring
└── cloud.rs             # Cloud storage operations and integrations
```

### Module Responsibilities

- **`main.rs`**: Application initialization, system tray management, eframe app implementation
- **`types.rs`**: Data structures (`App`, `SensitiveData`, `KeyVersion`), key lifecycle management
- **`crypto.rs`**: Encryption/decryption, digital signatures, password generation and assessment
- **`ui.rs`**: GUI components, tab management, user interaction handling
- **`backup.rs`**: File watching, deduplication, backup lifecycle management
- **`cloud.rs`**: Cloud provider integrations, upload/download operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is for educational and research purposes. While it implements cryptographic best practices, it has not been audited for production use. Always backup your mnemonic phrases securely.
