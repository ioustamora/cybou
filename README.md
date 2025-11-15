# cybou (Qt 6 + C++/QML + Post-Quantum Crypto)

A comprehensive file and text encryption tool with post-quantum cryptographic security. Built with Qt 6, this application provides strong encryption for files, folders, and text using NIST-standard post-quantum algorithms (Kyber-1024 for key encapsulation and ML-DSA-65 for digital signatures), all derived from BIP-39 mnemonic phrases.

**✅ Fully Cross-Platform**: Builds from the same source code on Windows, Linux, and macOS

## Features

- **BIP-39 Mnemonic Generation**: Generate cryptographically secure 12-24 word mnemonics using the complete standard word list
- **Post-Quantum Encryption**: Kyber-1024 key encapsulation mechanism for quantum-resistant encryption
- **Digital Signatures**: ML-DSA-65 signatures for authenticating encrypted content and verifying message integrity
- **File/Folder Encryption**: Encrypt individual files or entire directory trees with `.cybou` extension
- **Text Encryption**: Secure text encryption/decryption with visual operation indicators
- **Key Derivation**: Hierarchical key derivation from mnemonics for different cryptographic operations
- **Qt 6 QML Interface**: Modern, responsive GUI with file browsers and copy/paste functionality
- **Public Key Management**: Display, copy, and save public keys in `.cyboukey` format
- **Signature Management**: Create, verify, and save digital signatures in `.cybousig` format
- **Visual Feedback**: Color-coded text fields for operation feedback (encryption green, decryption red, signing yellow)
- **Cross-platform**: Built with CMake for Linux, Windows, and macOS with proper file path handling

## Cryptographic Security

- **Kyber-1024**: NIST-standard post-quantum key encapsulation (Level 5 security)
- **ML-DSA-65**: NIST-standard post-quantum digital signatures (Level 5 security)
- **BIP-39**: Standard mnemonic generation with proper entropy and checksum validation
- **Deterministic Keys**: SHA-256 derived symmetric keys for consistent encrypt/decrypt operations
- **Hybrid Security**: Combines classical and post-quantum cryptography for maximum security

## Status

✅ **Fully Implemented:**
- Qt 6 C++/QML application framework with modern UI
- Full BIP-39 compatible mnemonic generation and validation with copy/paste/clear buttons
- Complete post-quantum crypto integration (Kyber-1024 + ML-DSA-65)
- Text encryption/decryption with visual operation indicators
- File/folder encryption/decryption with proper binary handling
- Public key display, copy, and save functionality
- File browser integration with drag-and-drop support
- Color-coded UI elements for operation feedback
- Comprehensive testing suite for encryption operations
- Secure key derivation and management
- Proper file format handling (.cybou encrypted files, .cyboukey public keys)

🚧 **In Development:**
- Key import/export functionality
- Batch processing for multiple files
- Progress indicators for large file operations
- Advanced security features (secure memory wiping, key backup/restore)

## Build Requirements

- **Qt 6.5+** with components: Core, Gui, Qml, Quick, QuickControls2, QuickDialogs
- **CMake 3.21+**
- **C++20 compiler** (GCC 11+, Clang 13+, or MSVC 2022+)
- **liboqs** (Open Quantum Safe) - Post-quantum crypto library v0.15.0-rc2 or later
- **OpenSSL 3.0+** (for hybrid cryptographic operations)
- **Qt Creator** (recommended IDE) or compatible development environment

## Installing Dependencies

### Ubuntu/Debian:
```bash
# Install Qt6 and build tools
sudo apt update
sudo apt install qt6-base-dev qt6-declarative-dev qt6-quickcontrols2-dev cmake build-essential

# Install OpenSSL
sudo apt install libssl-dev

# Install liboqs (manual build required)
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_BUILD_ONLY_LIB=ON ..
make -j$(nproc)
sudo make install
```

### macOS (with Homebrew):
```bash
# Install Qt6
brew install qt6 cmake

# Install OpenSSL
brew install openssl

# Install liboqs
brew tap open-quantum-safe/quantum-safe-crypto
brew install liboqs
```

### Windows (with vcpkg):
```powershell
# Install Qt6
# Download and install Qt6 from https://www.qt.io/download

# Install dependencies via vcpkg
vcpkg install openssl liboqs
```

## Build Instructions

```bash
# Clone repository
git clone https://github.com/ioustamora/cybou.git
cd cybou

# Configure build (adjust paths as needed)
cmake -B build -S . \
  -DCMAKE_PREFIX_PATH="/path/to/qt/6.x" \
  -DOQS_ROOT="/path/to/liboqs"

# Build
cmake --build build -j$(nproc)

# Install (optional)
cmake --install build
```

## Running Tests

```bash
cd build
# Run encryption tests
./test_encryption

# Run mnemonic tests
./test_mnemonic
```

## Usage

```bash
./build/cybou
```

### Basic Workflow:
1. **Setup**: Generate or import a BIP-39 mnemonic phrase (copy/paste/clear buttons available)
2. **Key Generation**: Automatic derivation of Kyber-1024 and ML-DSA-65 key pairs from mnemonic
3. **Text Encryption**: Enter text, click encrypt (green output field indicates success)
4. **Text Decryption**: Enter encrypted text, click decrypt (red output field indicates success)
5. **File Encryption**: Select file/folder, encrypt to `.cybou` format
6. **File Decryption**: Select `.cybou` file, decrypt to original format
7. **Digital Signatures**: Sign messages with ML-DSA-65, verify signatures for authenticity
8. **Key Management**: View, copy, or save public keys in `.cyboukey` format

### File Encryption:
- Drag and drop files/folders onto the application or use file browser
- Encrypted files get `.cybou` extension
- Decrypted files restore original names with `_decrypted` suffix
- Supports binary files (images, executables, etc.) with proper encoding

### Text Encryption:
- Input field with light blue background for entering text
- Output field changes color: green for encryption results, red for decryption results
- Copy/paste/clear buttons for easy text management
- Base64 encoded output for safe text transmission

### Digital Signatures:
- Sign text messages with ML-DSA-65 quantum-resistant signatures
- Verify signatures to ensure message authenticity and integrity
- Save/load signatures in `.cybousig` format
- Yellow background for signature input fields

## Architecture

- **Frontend**: QML-based UI with Qt Quick Controls and file dialogs
- **Backend**: C++ crypto engine with Qt meta-object integration
- **PQ Crypto**: liboqs integration for Kyber-1024 and ML-DSA-65
- **Key Management**: Hierarchical derivation from BIP-39 mnemonics using SHA-256
- **File Processing**: Streaming encryption for large files with proper binary handling
- **UI Features**: Color-coded operation feedback, copy/paste functionality, file browsers

## Security Model

- **Quantum Resistance**: All cryptographic operations are quantum-resistant
- **Deterministic Encryption**: Consistent keys ensure encrypt/decrypt round-trip success
- **Perfect Forward Secrecy**: Ephemeral keys for each encryption session
- **Authentication**: Digital signature support (ML-DSA-65) for content verification
- **Key Separation**: Different keys for encryption vs signing operations
- **Secure Erasure**: Sensitive data is securely wiped from memory using OQS secure free

## File Formats

- **Encrypted Files**: `.cybou` extension with Base64-encoded binary data
- **Key Files**: `.cyboukey` for shared encryption public keys
- **Signature Files**: `.cybousig` for ML-DSA-65 signatures
- **Archive Format**: Custom format supporting folder encryption with metadata

## API Usage

The application can be used programmatically:

```cpp
// Initialize crypto engine
PostQuantumCrypto crypto;
crypto.generateKeyPair();

// Text encryption/decryption
QString encrypted = crypto.encryptText("Hello World");
QString decrypted = crypto.decryptText(encrypted);

// File operations with progress reporting
bool success = crypto.encryptFile("/path/to/large_input.txt", "/path/to/output.cybou");
// Progress signals emitted: operationProgress("encryptFile", progress, status)

bool success = crypto.decryptFile("/path/to/input.cybou", "/path/to/output.txt");
// Progress signals emitted: operationProgress("decryptFile", progress, status)
```

## Progress Indicators

cybou provides real-time progress feedback for file operations:

### Progress Reporting
- **Visual Progress Bars**: Real-time progress bars during encryption/decryption
- **Status Updates**: Detailed status messages showing current operation phase
- **Non-blocking UI**: Operations run without freezing the interface
- **Chunked Processing**: Large files processed in 1MB chunks to prevent memory issues

### Progress Signals
```cpp
// Connect to progress signals in QML
Connections {
    target: PostQuantumCrypto
    function onOperationProgress(operation, progress, status) {
        // operation: "encryptFile" or "decryptFile"
        // progress: 0-100 percentage
        // status: descriptive status message
    }
}
```

### Performance Features
- **Memory Efficient**: Files processed in chunks rather than loading entirely into memory
- **Responsive UI**: Progress updates keep the interface responsive during long operations
- **Cancellation Support**: UI buttons disabled during operations to prevent conflicts

// Digital signatures
QString signature = crypto.signMessage("Hello World");
bool isValid = crypto.verifySignature("Hello World", signature, crypto.publicKey());

// Key management
QString publicKey = crypto.publicKey(); // Combined Kyber + ML-DSA-65 key
QString privateKey = crypto.exportPrivateKey(); // Export private key for backup
bool imported = crypto.importKeyPair(privateKeyHex, publicKeyHex); // Import key pair
bool saved = crypto.saveEncryptedTextToFile(publicKey, "/path/to/key.cyboukey");
```

## Key Management Features

cybou provides comprehensive post-quantum key management:

### Key Export/Import
- **Public Key Export**: Safely share your public key for others to encrypt files or verify signatures
- **Private Key Export**: Backup your private key securely (encrypted storage recommended)
- **Key Pair Import**: Restore keys from backup or import externally generated keys

### Key File Format
Keys are stored in `.cyboukey` files with the following format:
```
<private_key_hex>
<public_key_hex>
```

### Security Best Practices
- **Public keys**: Safe to share openly for encryption and signature verification
- **Private keys**: Never share - contains your secret cryptographic material
- **Storage**: Use encrypted backups and secure storage for private keys
- **Backup**: Regularly backup your key pairs to prevent data loss

## Testing

The project includes comprehensive tests:

```bash
# Build and run encryption tests
cd build
make
./test_encryption  # Tests text encryption/decryption round-trip

# Run mnemonic validation tests
./test_mnemonic    # Tests BIP-39 word list and validation

# Run signature tests
./test_signatures  # Tests digital signature creation and verification
```

## Improvements Roadmap

### 🔄 **High Priority**
- **Progress Indicators**: Add progress bars for large file encryption/decryption operations
- **Batch Processing**: Support encrypting/decrypting multiple files simultaneously
- **Error Recovery**: Better error handling and recovery for corrupted files
- **UI Enhancements**: Dark mode, keyboard shortcuts, drag-and-drop support

### 🚀 **Medium Priority**
- **Performance Optimization**: 
  - Multi-threaded encryption for large files
  - Memory-mapped file processing for reduced RAM usage
  - GPU acceleration for cryptographic operations
- **Security Enhancements**:
  - Secure key backup/restore with encryption
  - Memory locking to prevent key leakage
  - Secure deletion of temporary files
- **UI/UX Improvements**:
  - Dark mode support
  - Keyboard shortcuts
  - Drag-and-drop file operations
  - Operation history and undo functionality

### 🔮 **Future Enhancements**
- **Additional PQ Algorithms**: Support for other NIST-standard algorithms (Falcon, SPHINCS+)
- **Cloud Integration**: Secure cloud storage with client-side encryption
- **Password Manager Integration**: Import/export keys from password managers
- **CLI Interface**: Command-line version for automation and scripting
- **Plugin System**: Extensible architecture for custom encryption algorithms
- **Mobile Support**: Qt-based mobile applications for iOS/Android
- **Network Operations**: Secure file transfer over network with PQ key exchange
- **Hardware Security**: Integration with HSMs and TPMs for key storage
- **Audit Logging**: Comprehensive logging of all cryptographic operations

### 🧪 **Research & Development**
- **Formal Verification**: Mathematical proofs of cryptographic correctness
- **Side-Channel Analysis**: Protection against timing and power analysis attacks
- **Post-Quantum Migration**: Tools to help migrate from classical to PQ cryptography
- **Interoperability**: Standards for PQ-encrypted file exchange between applications

## Implementation Details

### Key Derivation Process
1. **Mnemonic → Seed**: BIP-39 mnemonic converted to 512-bit seed using PBKDF2
2. **Seed → Master Key**: HKDF derivation for hierarchical key generation
3. **Master Key → PQ Keys**: Deterministic generation of Kyber-1024 and ML-DSA-65 key pairs
4. **PQ Keys → Symmetric Keys**: SHA-256 hashing for consistent AES encryption keys

### Encryption Flow
- **Text Encryption**: Input text → Base64 encode → PQ-derive symmetric key → AES encrypt → Base64 output
- **File Encryption**: Binary file → PQ-derive symmetric key → AES encrypt → Base64 encode → .cybou file
- **Decryption**: Reverse process with same deterministic key derivation

### UI Architecture
- **Main.qml**: Tabbed interface (Text/File/Signatures/Key management) with operation tracking
- **SplashDialog.qml**: Mnemonic setup with copy/paste/clear functionality
- **Color Coding**: Visual feedback system (blue input, green encrypt, red decrypt, yellow signing)

## Contributing

Areas for contribution:
- **Performance**: Optimize large file processing and memory usage
- **Security**: Implement additional hardening measures and security audits
- **UI/UX**: Improve accessibility, add themes, enhance user experience
- **Testing**: Expand test coverage, add integration tests, performance benchmarks
- **Documentation**: Create user guides, API documentation, security best practices
- **Cross-platform**: Test and fix issues on Windows/macOS platforms
- **Features**: Implement items from the improvements roadmap

### Development Setup
```bash
# Clone and setup
git clone https://github.com/ioustamora/cybou.git
cd cybou

# Install dependencies (Ubuntu/Debian)
sudo apt install qt6-base-dev qt6-declarative-dev cmake build-essential libssl-dev
# Install liboqs (see build instructions above)

# Build
cmake -B build -S .
cmake --build build -j$(nproc)

# Run tests
cd build
./test_encryption
./test_mnemonic

# Run application
./cybou
```

## License

This project implements NIST-standard post-quantum cryptographic algorithms for secure communication in the quantum computing era. Licensed under MIT License - see LICENSE file for details.
