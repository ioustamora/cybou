cmake_minimum_required(VERSION 3.21)
project(cybou LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.5 COMPONENTS Core Gui Qml Quick QuickControls2 REQUIRED)

# Find liboqs for post-quantum cryptography
# find_package(PkgConfig REQUIRED)
# pkg_check_modules(OQS REQUIRED IMPORTED_TARGET liboqs)
set(OQS_LIBRARIES /home/user/liboqs/build/lib/liboqs.so)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

qt_add_executable(cybou
    src/main.cpp
    src/crypto/MnemonicEngine.cpp
    src/crypto/PostQuantumCrypto.cpp
    resources.qrc
)

qt_add_qml_module(cybou
    URI CybouWallet
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/SplashDialog.qml
)

set_target_properties(cybou PROPERTIES
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

target_link_libraries(cybou
    PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Qml
        Qt6::Quick
        Qt6::QuickControls2
        ${OQS_LIBRARIES}
        OpenSSL::Crypto
)

install(TARGETS cybou
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
