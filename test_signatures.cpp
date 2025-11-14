#include <QCoreApplication>
#include <QDebug>
#include "src/crypto/PostQuantumCrypto.h"

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    PostQuantumCrypto crypto;
    
    // Generate keys
    if (!crypto.generateKeyPair()) {
        qDebug() << "Failed to generate keys";
        return 1;
    }
    
    QString testMessage = "Hello, quantum world! This is a test message for digital signatures.";
    qDebug() << "Test message:" << testMessage;
    
    // Sign the message
    QString signature = crypto.signMessage(testMessage);
    if (signature.isEmpty()) {
        qDebug() << "Failed to sign message";
        return 1;
    }
    qDebug() << "Signature created successfully";
    qDebug() << "Signature length (hex):" << signature.length();
    
    // Get the public key
    QString pubKey = crypto.publicKey();
    qDebug() << "Public key length (hex):" << pubKey.length();
    
    // Convert signature back to bytes for length check
    QByteArray sigBytes = QByteArray::fromHex(signature.toUtf8());
    qDebug() << "Signature length (bytes):" << sigBytes.size();
    qDebug() << "Expected signature length:" << OQS_SIG_ml_dsa_65_length_signature;
    
    // Verify the signature
    bool isValid = crypto.verifySignature(testMessage, signature, pubKey);
    if (isValid) {
        qDebug() << "✅ Signature verification successful!";
    } else {
        qDebug() << "❌ Signature verification failed!";
        return 1;
    }
    
    // Test with wrong message
    bool wrongMessageValid = crypto.verifySignature("Wrong message", signature, pubKey);
    if (!wrongMessageValid) {
        qDebug() << "✅ Wrong message correctly rejected";
    } else {
        qDebug() << "❌ Wrong message incorrectly accepted";
        return 1;
    }
    
    qDebug() << "All digital signature tests passed!";
    return 0;
}
