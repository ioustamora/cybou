# Cybou Roadmap

This document outlines the planned development roadmap for Cybou, the secure cryptography application.

## 🎯 Current Status (v0.5.1 - Mnemonic-Based Security)

### ✅ Completed Features

- **Core Cryptography**: PQ encryption/decryption with Kyber + AES-GCM/ChaCha20-Poly1305 hybrid scheme
- **Digital Signatures**: Dilithium-based signing (verification API needs update)
- **Mnemonic Integration**: BIP39 key derivation from 12/24-word phrases with secure validation
- **GUI Framework**: Cross-platform interface with Slint
- **File Operations**: Text, file, and folder encryption/decryption with standardized extensions
- **System Tray**: Enhanced tray icon with menu integration
- **Security**: Secure memory management with zeroize
- **Password Tools**: Secure password generation and strength assessment ✅
- **Backup System**: Complete automated backup with file watching ✅
  - Real-time file system monitoring
  - Content-based deduplication
  - Progress tracking and statistics
  - Backup verification and integrity checking
  - Automatic cleanup of old backups
- **Cloud Storage**: AWS S3 integration with encrypted uploads/downloads ✅
  - Secure cloud storage with existing encryption
  - Multi-provider architecture (AWS implemented, GCP/Azure planned)
  - Real-time upload/download operations
- **Advanced Cryptography**: Key rotation and multi-algorithm support ✅
  - Key versioning system with timestamp tracking
  - Automatic key rotation with backward compatibility
  - Key management UI with version history
  - Key metadata export/import functionality
- **Modular Architecture**: Refactored codebase with clear separation of concerns ✅
  - Organized into focused modules (types, crypto, ui, backup, cloud, windows)
  - Comprehensive unit test coverage
  - Improved maintainability and code organization
- **User Experience**: Enhanced interface with modern features ✅
  - Multi-window architecture with dedicated function windows
  - Main dashboard with key status and public key display
  - Public key copy/export functionality
  - File extension standardization (.cybou for encrypted, _decrypted for decrypted)
- **Mnemonic Workflow**: Complete mnemonic-based security implementation ✅
  - Automatic dashboard transition after key loading
  - Secure key derivation and storage
  - Public key management and export

## 🚀 Planned Features

### Phase 1: UI Completion & Polish (v0.6.0)

- [ ] **File Encryption UI**: Complete file encryption/decryption interface
- [ ] **Digital Signatures Fix**: Update Dilithium verification API compatibility
- [ ] **Folder Encryption UI**: Folder encryption/decryption interface
- [ ] **Settings UI**: Application settings and configuration
- [ ] **Key Management UI**: Enhanced key management interface
- [ ] **UI Polish**: Consistent styling and user experience improvements

### Phase 2: Cloud Integration Expansion (v0.7.0)

- [ ] **Google Cloud Storage**: GCP integration
- [ ] **Azure Blob Storage**: Microsoft Azure support
- [ ] **Multi-region Replication**: Geographic redundancy options
- [ ] **Cloud Sync**: Bidirectional synchronization with local files

### Phase 3: Advanced Security Features (v0.8.0)

- [ ] **Multi-signature**: Threshold cryptography support
- [ ] **Hardware Security**: Integration with HSMs/TPM
- [ ] **FIPS Compliance**: FIPS 140-3 validation preparation
- [ ] **Key Persistence**: Secure key storage between sessions

### Phase 4: Enhanced UX & Performance (v0.9.0)

- [ ] **Performance Optimization**: Memory usage and processing speed improvements
- [ ] **Advanced Accessibility**: Enhanced screen reader and keyboard navigation
- [ ] **Additional Languages**: Support for Japanese, Korean, Russian, Arabic
- [ ] **Network Operations**: Secure file transfer and remote encryption

### Phase 5: Performance & Scale (v1.0.0)

- [ ] **Parallel Processing**: Multi-threaded encryption/decryption
- [ ] **GPU Acceleration**: CUDA/OpenCL support for crypto operations
- [ ] **Streaming Encryption**: Large file streaming without full memory load
- [ ] **Database Integration**: Efficient metadata storage
- [ ] **Load Balancing**: Distributed processing support

## 🔧 Technical Improvements

### Code Quality

- [ ] **Unit Tests**: Comprehensive test coverage for crypto operations
- [ ] **Integration Tests**: End-to-end testing framework
- [ ] **Performance Benchmarks**: Crypto operation benchmarking
- [ ] **Memory Safety Audit**: Formal verification of memory handling
- [ ] **Security Audit**: Third-party security assessment

### User Experience

- [ ] **Mobile App**: iOS/Android companion apps
- [ ] **Web Interface**: Browser-based access option
- [ ] **Plugin System**: Extensible architecture for custom operations

### Platform Support

- [ ] **Linux Packaging**: .deb/.rpm packages
- [ ] **macOS App Store**: Apple App Store distribution
- [ ] **Windows MSI**: Microsoft Installer packages
- [ ] **Docker Container**: Containerized deployment
- [ ] **WebAssembly**: Browser-based version

## 📊 Metrics & Milestones

### v0.5.1 (Current) ✅ COMPLETED

- Mnemonic-based security implementation
- Slint GUI framework migration
- Public key display and export functionality
- File extension standardization
- Main dashboard with key status

### v0.6.0 (Q1 2025) - NEXT

- Complete UI implementation for all features
- Digital signatures verification fix
- Settings and configuration UI
- Enhanced key management

### v0.7.0 (Q2 2025)

- Expanded cloud storage support
- Multi-provider cloud integration
- Cloud synchronization features

### v0.8.0 (Q3 2025)

- Advanced security features
- Hardware security integration
- Key persistence between sessions

### v1.0.0 (Q4 2025)

- Production-ready release
- Security audit completed
- Enterprise deployment ready

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Priority Areas for Contributors

1. **UI Completion**: Implementing remaining UI components
2. **API Updates**: Fixing Dilithium verification and other crypto APIs
3. **Cloud Integration**: Additional storage provider support
4. **Testing**: Unit and integration test coverage
5. **Documentation**: User guides and API docs
6. **Performance**: Optimization and benchmarking

## 📝 Notes

- Timeline estimates are subject to change based on community contributions and funding
- Security features take priority over new functionality
- All cryptographic implementations will be reviewed by security experts
- Backward compatibility will be maintained where possible

## 📞 Contact

For roadmap discussions, feature requests, or contributions:

- GitHub Issues: [Project Issues](https://github.com/username/cybou/issues)
- Discussions: [Project Discussions](https://github.com/username/cybou/discussions)
- Security: `security@cybou-project.org`
