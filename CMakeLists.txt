cmake_minimum_required(VERSION 3.21)
project(qpq-encryptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.5 COMPONENTS Core Gui Qml Quick QuickControls2 REQUIRED)

# Find liboqs for post-quantum cryptography
find_package(PkgConfig REQUIRED)
pkg_check_modules(OQS REQUIRED IMPORTED_TARGET liboqs)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

qt_add_executable(qpq-encryptor
    src/main.cpp
    src/crypto/MnemonicEngine.cpp
    src/crypto/PostQuantumCrypto.cpp
    resources.qrc
)

qt_add_qml_module(qpq-encryptor
    URI QPQWallet
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/SplashDialog.qml
)

set_target_properties(qpq-encryptor PROPERTIES
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

target_link_libraries(qpq-encryptor
    PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Qml
        Qt6::Quick
        Qt6::QuickControls2
        PkgConfig::OQS
        OpenSSL::Crypto
)

install(TARGETS qpq-encryptor
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
