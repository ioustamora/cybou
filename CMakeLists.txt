# Cybou - Post-Quantum Encryption Application
# ============================================
#
# CMake build configuration for the Cybou Qt application.
# This project implements post-quantum cryptography using Kyber-1024
# and ML-DSA-65 algorithms for secure encryption in the quantum era.
#
# Dependencies:
# - Qt6 (Core, Gui, Qml, Quick, QuickControls2)
# - liboqs (Open Quantum Safe library)
# - OpenSSL (for additional cryptographic functions)
#
# Build targets:
# - cybou: Main Qt application
# - test_encryption: Encryption test suite
# - test_mnemonic: Mnemonic generation tests

cmake_minimum_required(VERSION 3.21)
project(cybou LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6 components required for the application
find_package(Qt6 6.5 COMPONENTS Core Gui Qml Quick QuickControls2 REQUIRED)

# Find liboqs for post-quantum cryptography
# Note: Using pkg-config for proper library detection
find_package(PkgConfig REQUIRED)
pkg_check_modules(OQS REQUIRED IMPORTED_TARGET liboqs)

# Find OpenSSL for classical cryptographic operations
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

# Main application executable
qt_add_executable(cybou
    src/main.cpp
    src/crypto/KeyManager.cpp
    src/crypto/EncryptionEngine.cpp
    src/crypto/SignatureEngine.cpp
    src/crypto/MnemonicEngine.cpp
    src/crypto/PostQuantumCrypto.cpp
    resources.qrc
)

# QML module for the application's user interface
qt_add_qml_module(cybou
    URI CybouWallet
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/SplashDialog.qml
        qml/components/TextEncryptionTab.qml
        qml/components/FileEncryptionTab.qml
        qml/components/SignatureTab.qml
        qml/components/KeyManagementTab.qml
)

# Set executable properties for different platforms
set_target_properties(cybou PROPERTIES
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# Link libraries
target_link_libraries(cybou
    PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Qml
        Qt6::Quick
        Qt6::QuickControls2
        PkgConfig::OQS        # Post-quantum crypto library
        OpenSSL::Crypto         # Classical crypto library
)

# Installation configuration
install(TARGETS cybou
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Test executables
add_executable(test_encryption 
    test_encryption.cpp 
    src/crypto/KeyManager.cpp
    src/crypto/EncryptionEngine.cpp
    src/crypto/SignatureEngine.cpp
    src/crypto/PostQuantumCrypto.cpp 
    src/crypto/MnemonicEngine.cpp
)
target_link_libraries(test_encryption
    PRIVATE
        Qt6::Core
        PkgConfig::OQS
        OpenSSL::Crypto
)
target_include_directories(test_encryption PRIVATE src)

add_executable(test_signatures 
    test_signatures.cpp 
    src/crypto/KeyManager.cpp
    src/crypto/EncryptionEngine.cpp
    src/crypto/SignatureEngine.cpp
    src/crypto/PostQuantumCrypto.cpp
)
target_link_libraries(test_signatures
    PRIVATE
        Qt6::Core
        PkgConfig::OQS
        OpenSSL::Crypto
)
target_include_directories(test_signatures PRIVATE src)
