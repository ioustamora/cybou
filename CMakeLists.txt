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
find_package(Qt6 6.5 COMPONENTS Core Gui Qml Quick QuickControls2 Test REQUIRED)

# Find liboqs for post-quantum cryptography
# Try pkg-config first, fall back to manual paths if not available
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(OQS IMPORTED_TARGET liboqs)
endif()

if(NOT OQS_FOUND)
    # Manual fallback for Windows/MSYS2
    find_path(OQS_INCLUDE_DIR oqs/oqs.h
        PATHS C:/msys64/mingw64/include
        NO_DEFAULT_PATH)
    find_library(OQS_LIBRARY NAMES oqs liboqs
        PATHS C:/msys64/mingw64/lib
        NO_DEFAULT_PATH)
    if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
        set(OQS_FOUND TRUE)
        add_library(PkgConfig::OQS UNKNOWN IMPORTED)
        set_target_properties(PkgConfig::OQS PROPERTIES
            IMPORTED_LOCATION "${OQS_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OQS_INCLUDE_DIR}")
        message(STATUS "Found liboqs: ${OQS_LIBRARY}")
    else()
        message(FATAL_ERROR "Could not find liboqs library")
    endif()
endif()

# Find OpenSSL for classical cryptographic operations
find_package(OpenSSL QUIET)
if(NOT OPENSSL_FOUND)
    # Manual fallback for Windows/MSYS2
    find_path(OPENSSL_INCLUDE_DIR openssl/ssl.h
        PATHS C:/msys64/mingw64/include
        NO_DEFAULT_PATH)
    find_library(OPENSSL_CRYPTO_LIBRARY NAMES crypto libcrypto
        PATHS C:/msys64/mingw64/lib
        NO_DEFAULT_PATH)
    find_library(OPENSSL_SSL_LIBRARY NAMES ssl libssl
        PATHS C:/msys64/mingw64/lib
        NO_DEFAULT_PATH)
    if(OPENSSL_INCLUDE_DIR AND OPENSSL_CRYPTO_LIBRARY AND OPENSSL_SSL_LIBRARY)
        set(OPENSSL_FOUND TRUE)
        set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
        # Create imported targets for compatibility
        add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::Crypto PROPERTIES
            IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
        add_library(OpenSSL::SSL UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::SSL PROPERTIES
            IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
        message(STATUS "Found OpenSSL: ${OPENSSL_LIBRARIES}")
    else()
        message(FATAL_ERROR "Could not find OpenSSL library")
    endif()
endif()

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

# New unit test executables for individual modules
add_executable(test_keymanager
    test_keymanager.cpp
    src/crypto/KeyManager.cpp
)
target_link_libraries(test_keymanager
    PRIVATE
        Qt6::Core
        Qt6::Test
        PkgConfig::OQS
        OpenSSL::Crypto
)
target_include_directories(test_keymanager PRIVATE src)

add_executable(test_encryptionengine
    test_encryptionengine.cpp
    src/crypto/KeyManager.cpp
    src/crypto/EncryptionEngine.cpp
)
target_link_libraries(test_encryptionengine
    PRIVATE
        Qt6::Core
        Qt6::Test
        PkgConfig::OQS
        OpenSSL::Crypto
)
target_include_directories(test_encryptionengine PRIVATE src)

add_executable(test_signatureengine
    test_signatureengine.cpp
    src/crypto/KeyManager.cpp
    src/crypto/SignatureEngine.cpp
)
target_link_libraries(test_signatureengine
    PRIVATE
        Qt6::Core
        Qt6::Test
        PkgConfig::OQS
        OpenSSL::Crypto
)
target_include_directories(test_signatureengine PRIVATE src)

# Performance benchmark executable
add_executable(benchmark_crypto
    benchmark_crypto.cpp
    src/crypto/KeyManager.cpp
    src/crypto/EncryptionEngine.cpp
    src/crypto/SignatureEngine.cpp
)
target_link_libraries(benchmark_crypto
    PRIVATE
        Qt6::Core
        PkgConfig::OQS
        OpenSSL::Crypto
)
target_include_directories(benchmark_crypto PRIVATE src)
