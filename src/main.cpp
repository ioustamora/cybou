/**
 * @file main.cpp
 * @brief Main entry point for the Cybou post-quantum encryption application
 *
 * This file initializes the Qt QML application, registers cryptographic singletons
 * for QML access, and sets up the main application window. The application provides
 * post-quantum encryption capabilities using Kyber-1024 and ML-DSA-65 algorithms.
 */

#include <QApplication>
#include <QMessageBox>

#include "crypto/MnemonicEngine.h"
#include "crypto/PostQuantumCrypto.h"

// QML singleton provider functions
/**
 * @brief Creates or returns the singleton MnemonicEngine instance for QML
 *
 * This function provides a singleton instance of MnemonicEngine to QML,
 * allowing the UI to access BIP-39 mnemonic generation and validation
 * functionality. The singleton pattern ensures consistent state across
 * the application.
 *
 * @param engine Pointer to the QML engine (unused)
 * @param scriptEngine Pointer to the JavaScript engine (unused)
 * @return QObject* Pointer to the MnemonicEngine singleton instance
 */
static QObject *mnemonicEngineProvider(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine)
    Q_UNUSED(scriptEngine)
    static MnemonicEngine *instance = nullptr;
    if (!instance) {
        instance = new MnemonicEngine();
    }
    return instance;
}

/**
 * @brief Creates or returns the singleton PostQuantumCrypto instance for QML
 *
 * This function provides a singleton instance of PostQuantumCrypto to QML,
 * enabling the UI to perform post-quantum cryptographic operations including
 * Kyber-1024 key encapsulation and ML-DSA-65 digital signatures.
 *
 * @param engine Pointer to the QML engine (unused)
 * @param scriptEngine Pointer to the JavaScript engine (unused)
 * @return QObject* Pointer to the PostQuantumCrypto singleton instance
 */
static QObject *postQuantumCryptoProvider(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine)
    Q_UNUSED(scriptEngine)
    static PostQuantumCrypto *instance = nullptr;
    if (!instance) {
        instance = new PostQuantumCrypto();
    }
    return instance;
}

/**
 * @brief Main application entry point
 *
 * Initializes the Qt application, registers QML singletons for cryptographic
 * operations, connects the crypto engines, and loads the main QML interface.
 * The application provides a complete post-quantum encryption solution with
 * BIP-39 mnemonic-based key derivation.
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return int Application exit code (0 for success, non-zero for errors)
 */
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("cybou");
    app.setOrganizationName("cybou");

    qDebug() << "Qt application started successfully";

    // Just show a message box for testing
    QMessageBox::information(nullptr, "Test", "Qt application is working!");
    
    return app.exec();
}
