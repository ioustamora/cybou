# Cybou Roadmap

This document outlines the planned development roadmap for Cybou, the secure cryptography application.

## 🎯 Current Status (v0.4.0 - Advanced Cryptography)

### ✅ Completed Features

- **Core Cryptography**: PQ encryption/decryption with Kyber + AES-GCM hybrid scheme
- **Digital Signatures**: Dilithium-based signing and verification
- **Mnemonic Integration**: BIP39 key derivation from 12/24-word phrases
- **GUI Framework**: Cross-platform interface with eframe/egui
- **File Operations**: Text, file, and folder encryption/decryption
- **System Tray**: Basic tray icon with menu integration
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
  - Additional PQ algorithms (Falcon, SPHINCS+) integrated
  - Key management UI with version history
  - Key metadata export/import functionality
- **Modular Architecture**: Refactored codebase with clear separation of concerns ✅
  - Organized into focused modules (types, crypto, ui, backup, cloud)
  - Comprehensive unit test coverage (55 tests)
  - Improved maintainability and code organization
- **User Experience**: Enhanced interface with modern features ✅
  - Dark Mode: System theme integration with toggle and automatic application
  - Accessibility: Screen reader and keyboard navigation support framework
  - Internationalization: Multi-language support with language selection (English, Spanish, French, German, Chinese)

## 🚀 Planned Features

### Phase 1: Backup System Completion (v0.2.0) ✅ COMPLETED

- [x] **File Watching**: Implement actual folder monitoring with `notify` crate
- [x] **Deduplication**: Smart backup deduplication to avoid redundant storage
- [x] **Backup Scheduling**: Configurable automatic backup intervals (UI ready, scheduling pending)
- [x] **Backup Verification**: Integrity checking for backed up files
- [x] **Progress Indicators**: Real-time backup progress in UI

### Phase 2: Cloud Integration (v0.3.0) ✅ COMPLETED

- [x] **Cloud Storage API**: Abstract interface for cloud providers
- [x] **AWS S3 Support**: Integration with Amazon S3
- [x] **Encrypted Uploads**: End-to-end encrypted cloud storage
- [x] **Multi-provider Framework**: Support structure for GCP/Azure
- [ ] **Google Cloud Storage**: GCP integration (planned)
- [ ] **Azure Blob Storage**: Microsoft Azure support (planned)
- [ ] **Multi-region Replication**: Geographic redundancy options

### Phase 3: Advanced Cryptography (v0.4.0) ✅ COMPLETED

- [x] **Additional PQ Algorithms**: Support for Falcon, SPHINCS+ signatures
- [x] **Key Rotation**: Automatic key rotation with version management
- [x] **Key Versioning**: Timestamp-based key history and backward compatibility
- [x] **Key Management UI**: Interface for viewing and managing key versions
- [ ] **Multi-signature**: Threshold cryptography support
- [ ] **Hardware Security**: Integration with HSMs/TPM
- [ ] **FIPS Compliance**: FIPS 140-3 validation preparation

### Phase 4: Enhanced UX & Performance (v0.5.0)

- [ ] **Performance Optimization**: Memory usage and processing speed improvements
- [ ] **Advanced Accessibility**: Enhanced screen reader and keyboard navigation
- [ ] **Additional Languages**: Support for Japanese, Korean, Russian, Arabic
- [ ] **Hardware Security**: TPM/HSM integration for key storage
- [ ] **Network Operations**: Secure file transfer and remote encryption

### Phase 5: Performance & Scale (v0.6.0)

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

- [x] **Dark Mode**: System theme integration with toggle and automatic application
- [x] **Accessibility**: Screen reader and keyboard navigation support framework
- [x] **Internationalization**: Multi-language support with language selection (English, Spanish, French, German, Chinese)
- [ ] **Mobile App**: iOS/Android companion apps
- [ ] **Web Interface**: Browser-based access option

### Platform Support

- [ ] **Linux Packaging**: .deb/.rpm packages
- [ ] **macOS App Store**: Apple App Store distribution
- [ ] **Windows MSI**: Microsoft Installer packages
- [ ] **Docker Container**: Containerized deployment
- [ ] **WebAssembly**: Browser-based version

## 📊 Metrics & Milestones

### v0.3.0 (Q2 2026) ✅ COMPLETED

- Cloud storage integration
- AWS S3 support
- Multi-provider framework
- Performance optimizations

### v0.4.0 (Q3 2026) ✅ COMPLETED

- Advanced crypto algorithms (Falcon, SPHINCS+)
- Key rotation and versioning system
- Key management UI
- Enhanced security features

### v0.5.0 (Q4 2026) - NEXT

- Enhanced user experience features
- Performance optimizations
- Advanced accessibility support
- Hardware security integration
- Multi-language expansion

### v1.0.0 (Q1 2027)

- Production-ready release
- Security audit completed
- Enterprise deployment ready

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Priority Areas for Contributors

1. **Backup System**: File watching and deduplication
2. **Cloud Integration**: Storage provider APIs
3. **Testing**: Unit and integration test coverage
4. **Documentation**: User guides and API docs
5. **Performance**: Optimization and benchmarking

## 📝 Notes

- Timeline estimates are subject to change based on community contributions and funding
- Security features take priority over new functionality
- All cryptographic implementations will be reviewed by security experts
- Backward compatibility will be maintained where possible

## 📞 Contact

For roadmap discussions, feature requests, or contributions:

- GitHub Issues: [Project Issues](https://github.com/username/cybou/issues)
- Discussions: [Project Discussions](https://github.com/username/cybou/discussions)
- Security: security@cybou-project.org
