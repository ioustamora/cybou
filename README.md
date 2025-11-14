# cybou (Qt 6 + C++/QML + Post-Quantum Crypto)

A comprehensive file and text encryption tool with post-quantum cryptographic security. Built with Qt 6, this application provides strong encryption for files, folders, and text using NIST-standard post-quantum algorithms (Kyber-1024 for key encapsulation and CRYSTALS-Dilithium for digital signatures), all derived from BIP-39 mnemonic phrases.

## Features

- **BIP-39 Mnemonic Generation**: Generate cryptographically secure 12-24 word mnemonics using the complete standard word list
- **Post-Quantum Encryption**: Kyber-1024 key encapsulation mechanism for quantum-resistant encryption
- **Digital Signatures**: CRYSTALS-Dilithium signatures for authenticating encrypted content
- **File/Folder Encryption**: Encrypt individual files or entire directory trees
- **Text Encryption**: Secure text encryption/decryption with PQ key exchange
- **Key Derivation**: Hierarchical key derivation from mnemonics for different cryptographic operations
- **Qt 6 QML Interface**: Modern, responsive GUI with drag-and-drop file support
- **Cross-platform**: Built with CMake for Linux, Windows, and macOS

## Cryptographic Security

- **Kyber-1024**: NIST-standard post-quantum key encapsulation (Level 5 security)
- **CRYSTALS-Dilithium**: NIST-standard post-quantum digital signatures (Level 5 security)
- **BIP-39**: Standard mnemonic generation with proper entropy and checksum validation
- **Hybrid Security**: Combines classical and post-quantum cryptography for maximum security

## Status

✅ **Implemented:**
- Qt 6 C++/QML application framework
- Full BIP-39 compatible mnemonic generation and validation
- Post-quantum crypto integration framework
- Basic key derivation and management
- Modal setup dialog with real-time validation
- File/folder encryption UI foundation

🚧 **In Development:**
- Kyber-1024 and Dilithium integration via liboqs
- File/folder encryption/decryption operations
- Digital signature creation and verification
- Secure key storage and backup/restore
- Batch processing for multiple files/folders

## Build Requirements

- Qt 6.5+ with components: Core, Gui, Qml, Quick, QuickControls2
- CMake 3.21+
- C++20 compiler (GCC 11+, Clang 13+, or MSVC 2022+)
- **liboqs** (Open Quantum Safe) - Post-quantum crypto library
- OpenSSL 3.0+ (for hybrid cryptographic operations)

## Installing Dependencies

### Ubuntu/Debian:
```bash
# Install Qt6
sudo apt install qt6-base-dev qt6-declarative-dev cmake build-essential

# Install liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install

# Install OpenSSL
sudo apt install libssl-dev
```

### macOS (with Homebrew):
```bash
# Install Qt6
brew install qt6 cmake

# Install liboqs
brew tap open-quantum-safe/quantum-safe-crypto
brew install liboqs

# Install OpenSSL
brew install openssl
```

## Build Instructions

```bash
cd /path/to/cybou
cmake -B build -S . -DCMAKE_PREFIX_PATH="/path/to/qt/6.x"
cmake --build build -j$(nproc)
```

## Usage

```bash
./build/cybou
```

### Basic Workflow:
1. **Setup**: Generate or import a BIP-39 mnemonic phrase
2. **Key Generation**: Automatic derivation of Kyber-1024 and Dilithium key pairs
3. **Encryption**: Select files/folders or enter text to encrypt
4. **Signatures**: Optionally sign encrypted content with Dilithium
5. **Decryption**: Use the same mnemonic to decrypt and verify signatures

### File Encryption:
- Drag and drop files/folders onto the application
- Choose encryption mode (confidentiality only or authenticated encryption)
- Encrypted files maintain original structure with `.qpq` extension

### Text Encryption:
- Enter text in the secure input area
- Generate one-time keys for each encryption session
- Share encrypted text with recipients who have the mnemonic

## Architecture

- **Frontend**: QML-based UI with Qt Quick Controls and file dialogs
- **Backend**: C++ crypto engine with Qt meta-object integration
- **PQ Crypto**: liboqs integration for Kyber-1024 and Dilithium
- **Key Management**: Hierarchical derivation from BIP-39 mnemonics
- **File Processing**: Streaming encryption for large files/folders

## Security Model

- **Quantum Resistance**: All cryptographic operations are quantum-resistant
- **Perfect Forward Secrecy**: Ephemeral keys for each encryption session
- **Authentication**: Digital signatures ensure content integrity
- **Key Separation**: Different keys for encryption vs signing operations
- **Secure Erasure**: Sensitive data is securely wiped from memory

## File Formats

- **Encrypted Files**: `.cybou` extension with metadata header
- **Key Files**: `.cyboukey` for shared encryption keys
- **Signature Files**: `.cybousig` for Dilithium signatures
- **Archive Format**: Custom format supporting folder encryption

## API Usage

The application can be used programmatically:

```cpp
// Initialize crypto engine
cybou encryptor;
encryptor.setMnemonic("your bip39 mnemonic here");

// Encrypt a file
encryptor.encryptFile("/path/to/input.txt", "/path/to/output.cybou");

// Decrypt a file
encryptor.decryptFile("/path/to/input.cybou", "/path/to/output.txt");

// Sign content
QString signature = encryptor.signData("Hello World");

// Verify signature
bool valid = encryptor.verifySignature("Hello World", signature, publicKey);
```

## Contributing

Areas for contribution:
- Performance optimizations for large file encryption
- Additional PQ algorithm support
- UI/UX improvements and accessibility
- Cross-platform testing and packaging
- Security audits and formal verification

## License

This project implements NIST-standard post-quantum cryptographic algorithms for secure communication in the quantum computing era.
