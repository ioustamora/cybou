#include <QCoreApplication>
#include <QDebug>
#include "src/crypto/PostQuantumCrypto.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    
    PostQuantumCrypto crypto;
    
    // Generate keys
    if (!crypto.generateKeyPair()) {
        qDebug() << "Failed to generate keys";
        return 1;
    }
    
    // Test text encryption/decryption
    QString originalText = "Hello, quantum world! This is a test message for cybou encryption.";
    qDebug() << "Original text:" << originalText;
    
    // Encrypt
    QString encrypted = crypto.encryptText(originalText);
    qDebug() << "Encrypted:" << encrypted;
    
    // Decrypt
    QString decrypted = crypto.decryptText(encrypted);
    qDebug() << "Decrypted:" << decrypted;
    
    // Check if they match
    if (originalText == decrypted) {
        qDebug() << "SUCCESS: Encryption/decryption works correctly!";
        return 0;
    } else {
        qDebug() << "FAILURE: Decrypted text doesn't match original!";
        return 1;
    }
}
