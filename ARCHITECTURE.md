# Cybou Architecture Documentation

## System Overview

Cybou is a post-quantum encryption application built with Qt 6 and C++/QML, implementing NIST-standard cryptographic algorithms (Kyber-1024 and ML-DSA-65) for quantum-resistant security.

## Architecture Layers

### 1. Presentation Layer (QML)
**Location**: `qml/`

#### Components Structure (Refactored)
```
qml/
├── Main.qml                    # Application shell, tab management
├── SplashDialog.qml            # Mnemonic setup dialog
└── components/
    ├── TextEncryptionTab.qml   # Text encryption UI
    ├── FileEncryptionTab.qml   # File encryption UI  
    ├── SignatureTab.qml        # Digital signatures UI
    └── KeyManagementTab.qml    # Key management UI
```

**Responsibilities**:
- User interface rendering
- User input handling
- Visual feedback and status display
- Component composition and layout
- Event routing to backend

**Key Patterns**:
- Component-based architecture for reusability
- Property bindings for reactive UI
- Signal/slot communication with C++ backend
- Separation of UI logic from business logic

### 2. Business Logic Layer (C++)
**Location**: `src/crypto/`

#### Module Structure (Refactored)

```
src/crypto/
├── KeyManager.{h,cpp}          # Key generation and management
├── EncryptionEngine.{h,cpp}    # Encryption/decryption operations
├── SignatureEngine.{h,cpp}     # Digital signatures and key exchange
├── PostQuantumCrypto.{h,cpp}   # Facade coordinating all modules
├── MnemonicEngine.{h,cpp}      # BIP-39 mnemonic operations
└── bip39_words.h               # BIP-39 word list data
```

#### Module Responsibilities

**KeyManager**:
- Generate Kyber-1024 + ML-DSA-65 key pairs
- Import/export keys (hex format)
- Secure memory management (OQS allocators)
- Deterministic key derivation for encryption
- Key lifecycle management

**EncryptionEngine**:
- Text encryption/decryption (Base64 encoded)
- File encryption/decryption (binary safe)
- Chunked processing for large files
- Progress reporting for long operations
- XOR-based symmetric encryption

**SignatureEngine**:
- Message signing with ML-DSA-65
- Signature verification
- Kyber key encapsulation
- Shared secret generation
- Public key operations

**PostQuantumCrypto** (Facade):
- Qt meta-object interface for QML
- Coordinates between modules
- Aggregates signals from sub-modules
- Maintains backward API compatibility
- Manages module lifecycle

**MnemonicEngine**:
- BIP-39 mnemonic generation (12/24 words)
- Mnemonic validation
- Seed derivation from mnemonic
- Key derivation from seed

### 3. Cryptography Layer
**Location**: External library (liboqs)

**Algorithms**:
- **Kyber-1024**: Key encapsulation mechanism (KEM)
  - Security Level: 5 (highest)
  - Public key: 1568 bytes
  - Secret key: 3168 bytes
  - Ciphertext: 1568 bytes
  
- **ML-DSA-65**: Digital signatures (formerly Dilithium5)
  - Security Level: 5 (highest)
  - Public key: 2592 bytes
  - Secret key: 4864 bytes
  - Signature: ~4627 bytes

## Data Flow

### Encryption Flow
```
User Input (QML)
    ↓
PostQuantumCrypto::encryptText()
    ↓
EncryptionEngine::encryptText()
    ↓
KeyManager::generateDeterministicKey()
    ↓
XOR Encryption + Base64 Encoding
    ↓
Encrypted Output (QML)
```

### File Encryption Flow
```
File Selection (QML)
    ↓
PostQuantumCrypto::encryptFile()
    ↓
EncryptionEngine::encryptFile()
    ├─→ Read file in chunks (1MB)
    ├─→ Encrypt each chunk
    ├─→ Emit progress signals
    └─→ Write to .cybou file
    ↓
Progress Updates (QML)
```

### Key Generation Flow
```
Generate Button Click (QML)
    ↓
PostQuantumCrypto::generateKeyPair()
    ↓
KeyManager::generateKeyPair()
    ├─→ OQS_KEM_kyber_1024_keypair()
    └─→ OQS_SIG_ml_dsa_65_keypair()
    ↓
keysChanged() signal
    ↓
UI Update (QML)
```

### Signature Flow
```
Sign Message (QML)
    ↓
PostQuantumCrypto::signMessage()
    ↓
SignatureEngine::signMessage()
    ↓
OQS_SIG_sign()
    ↓
Hex-encoded Signature (QML)
```

## Design Patterns

### 1. Facade Pattern
**PostQuantumCrypto** acts as a facade, providing a simplified interface to the complex subsystem of key management, encryption, and signatures.

```cpp
// Facade delegates to specialized modules
QString PostQuantumCrypto::encryptText(const QString &text) {
    return m_encryptionEngine->encryptText(text);
}

bool PostQuantumCrypto::generateKeyPair() {
    return m_keyManager->generateKeyPair();
}
```

### 2. Component Pattern (QML)
UI split into reusable, self-contained components with clear interfaces.

```qml
// Component with properties and signals
TextEncryptionTab {
    darkMode: mainWindow.darkMode
    onSaveTextRequested: saveTextDialog.open()
}
```

### 3. Signal/Slot Pattern
Qt's signal/slot mechanism for loose coupling between layers.

```cpp
// Backend emits signals
emit operationProgress("encryptFile", 50, "Processing...");

// QML connects to signals
Connections {
    target: PostQuantumCrypto
    function onOperationProgress(op, progress, status) {
        // Update UI
    }
}
```

### 4. Dependency Injection
Modules receive dependencies through constructor injection.

```cpp
// EncryptionEngine depends on KeyManager
EncryptionEngine::EncryptionEngine(KeyManager *keyManager, QObject *parent)
    : QObject(parent), m_keyManager(keyManager) {
}
```

## Security Architecture

### Memory Management
- **OQS Secure Allocators**: All key material uses `OQS_MEM_malloc()`
- **Secure Free**: Keys wiped with `OQS_MEM_secure_free()`
- **RAII Pattern**: Automatic cleanup in destructors
- **No Key Logging**: Debug output excludes sensitive data

### Key Derivation
```
Mnemonic (BIP-39)
    ↓ PBKDF2
512-bit Seed
    ↓ HKDF
Master Key
    ↓ SHA-256
Deterministic Symmetric Key (256-bit)
```

### Encryption Scheme
```
Plaintext
    ↓ UTF-8 Encode
Binary Data
    ↓ XOR with Derived Key
Ciphertext
    ↓ Base64 Encode
Transmittable String
```

### File Format
```
.cybou file:
- Base64-encoded encrypted data
- No header/metadata (privacy)
- Requires correct mnemonic to decrypt
```

## Threading Model

### Main Thread
- UI rendering (QML)
- User input handling
- Signal/slot processing

### Worker Threads
- Not yet implemented (planned)
- Will handle file I/O for large files
- Background encryption operations

### Thread Safety
- Current: Single-threaded, no concurrent access
- Future: Mutex protection for key access
- Qt's signal/slot is thread-safe

## Error Handling

### Levels
1. **Cryptographic Errors**: OQS library failures
2. **I/O Errors**: File read/write failures
3. **Validation Errors**: Invalid input/parameters
4. **UI Errors**: Display to user with guidance

### Strategy
```cpp
try {
    // Operation
    if (!result) {
        emit operationCompleted("op", false, "Error message");
        return false;
    }
} catch (std::exception &e) {
    qWarning() << "Exception:" << e.what();
    return false;
}
```

## Testing Strategy

### Unit Tests
- **KeyManager**: Key generation, import/export
- **EncryptionEngine**: Encrypt/decrypt round-trip
- **SignatureEngine**: Sign/verify validity
- **MnemonicEngine**: BIP-39 compliance

### Integration Tests
- **PostQuantumCrypto**: Facade functionality
- **QML Components**: User interactions
- **End-to-End**: Complete workflows

### Test Files
- `test_encryption.cpp`: Encryption tests
- `test_mnemonic.cpp`: Mnemonic tests
- `test_signatures.cpp`: Signature tests

## Build System

### CMake Structure
```cmake
cmake_minimum_required(VERSION 3.21)
project(cybou)

# Find Qt6 components
find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick)

# Add source files
add_executable(cybou
    src/main.cpp
    src/crypto/KeyManager.cpp
    src/crypto/EncryptionEngine.cpp
    src/crypto/SignatureEngine.cpp
    src/crypto/PostQuantumCrypto.cpp
    src/crypto/MnemonicEngine.cpp
)

# Link libraries
target_link_libraries(cybou PRIVATE Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick oqs)
```

## Performance Considerations

### File Processing
- **Chunked I/O**: 1MB chunks for large files
- **Progress Reporting**: Every 5% progress
- **Memory Efficient**: Streaming, not loading entire file

### Key Operations
- **Cached Public Key**: Avoid repeated hex conversion
- **Deterministic Derivation**: Consistent performance
- **Minimal Allocations**: Reuse buffers where possible

### UI Responsiveness
- **Non-blocking**: Operations don't freeze UI
- **Progress Signals**: Real-time feedback
- **Async Future**: Plan for Qt::Concurrent integration

## Extensibility Points

### Adding New Algorithms
1. Extend SignatureEngine for new signature schemes
2. Update KeyManager for additional key types
3. Maintain backward compatibility

### Adding New Features
- **Cloud Sync**: Add CloudStorageModule
- **Hardware Keys**: Add HardwareSecurityModule
- **Network Operations**: Add NetworkEngine

### Plugin Architecture (Future)
```cpp
class CryptoPlugin {
public:
    virtual QString name() const = 0;
    virtual bool encrypt(const QByteArray &data) = 0;
    virtual bool decrypt(const QByteArray &data) = 0;
};
```

## Dependencies

### External Libraries
- **Qt 6.5+**: Application framework
- **liboqs 0.14.0+**: Post-quantum cryptography
- **OpenSSL 3.0+**: Hybrid operations (future)

### Build Dependencies
- **CMake 3.21+**: Build system
- **C++20 compiler**: GCC 11+, Clang 13+, MSVC 2022+
- **pkg-config**: Library discovery

## Deployment

### Windows
- **Qt deployment**: windeployqt for dependencies
- **Installer**: NSIS or WiX for distribution
- **DLLs**: liboqs, OpenSSL bundled

### Linux
- **AppImage**: Self-contained distribution
- **Package**: .deb for Ubuntu, .rpm for Fedora
- **Dependencies**: System libraries preferred

### macOS
- **App Bundle**: .app with frameworks
- **Code Signing**: Required for distribution
- **Notarization**: Apple requirements

## Future Enhancements

### Planned (v2.0)
- Multi-threaded batch processing
- Memory-mapped file I/O
- Hardware security module integration
- Cloud backup with client-side encryption

### Research (v3.0)
- Additional PQ algorithms (Falcon, SPHINCS+)
- GPU acceleration for crypto operations
- Formal verification of crypto correctness
- Side-channel attack mitigation

---

**Version**: 2.0
**Last Updated**: November 15, 2025
**Maintainer**: Development Team
