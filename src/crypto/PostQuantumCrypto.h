#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QVariantMap>
#include <QFile>
#include <QTextStream>
#include <QCryptographicHash>

extern "C" {
#include <oqs/oqs.h>
}

// PostQuantumCrypto provides post-quantum cryptographic operations
// Uses Kyber-1024 for key encapsulation and CRYSTALS-Dilithium for digital signatures

class PostQuantumCrypto : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool hasKeys READ hasKeys NOTIFY keysChanged)
    Q_PROPERTY(QString publicKey READ publicKey NOTIFY keysChanged)
    Q_PROPERTY(QString keyAlgorithm READ keyAlgorithm CONSTANT)

public:
    explicit PostQuantumCrypto(QObject *parent = nullptr);
    ~PostQuantumCrypto();

    // Key management
    Q_INVOKABLE bool generateKeyPair();
    Q_INVOKABLE bool importKeyPair(const QString &privateKeyHex, const QString &publicKeyHex);
    Q_INVOKABLE QString exportPrivateKey() const;
    Q_INVOKABLE QString exportPublicKey() const;

    // Cryptographic operations
    Q_INVOKABLE QString signMessage(const QString &message);
    Q_INVOKABLE bool verifySignature(const QString &message, const QString &signature, const QString &publicKeyHex);

    // Key encapsulation with Kyber-1024
    Q_INVOKABLE QVariantMap encapsulateKey(const QString &recipientPublicKeyHex);
    Q_INVOKABLE QByteArray decapsulateKey(const QVariantMap &encapsulatedKey);

    // Text encryption/decryption using PQ-derived symmetric keys
    Q_INVOKABLE QString encryptText(const QString &plaintext);
    Q_INVOKABLE QString decryptText(const QString &ciphertext);

    // File operations for encrypted text
    Q_INVOKABLE bool saveEncryptedTextToFile(const QString &content, const QString &filePath);
    Q_INVOKABLE QString loadEncryptedTextFromFile(const QString &filePath);

    // File encryption/decryption operations
    Q_INVOKABLE bool encryptFile(const QString &inputFilePath, const QString &outputFilePath);
    Q_INVOKABLE bool decryptFile(const QString &inputFilePath, const QString &outputFilePath);

    // Binary data encryption/decryption (for proper file handling)
    Q_INVOKABLE QByteArray encryptBinary(const QByteArray &plaintext);
    Q_INVOKABLE QByteArray decryptBinary(const QByteArray &ciphertext);

    // Utility functions
    Q_INVOKABLE QString generateSharedSecret(const QString &otherPublicKeyHex);

    // Property accessors
    bool hasKeys() const { return m_kyberPublicKey != nullptr && m_dilithiumPublicKey != nullptr; }
    QString publicKey() const { return m_publicKeyHex; }
    QString keyAlgorithm() const { return QStringLiteral("Kyber-1024/Dilithium"); }

signals:
    void keysChanged();
    void operationCompleted(const QString &operation, bool success, const QString &result);

private:
    // Kyber-1024 key pair
    uint8_t *m_kyberPublicKey = nullptr;
    uint8_t *m_kyberSecretKey = nullptr;

    // CRYSTALS-Dilithium key pair
    uint8_t *m_dilithiumPublicKey = nullptr;
    uint8_t *m_dilithiumSecretKey = nullptr;

    QString m_publicKeyHex;

    // PQ crypto operations
    bool initializeOQS();
    void cleanupKeys();
    QByteArray kyberEncapsulate(const uint8_t *publicKey, size_t publicKeyLen);
    QByteArray kyberDecapsulate(const QByteArray &ciphertext, const uint8_t *secretKey, size_t secretKeyLen);
    QByteArray dilithiumSign(const QByteArray &message, const uint8_t *secretKey, size_t secretKeyLen);
    bool dilithiumVerify(const QByteArray &message, const QByteArray &signature, const uint8_t *publicKey, size_t publicKeyLen);
    QByteArray generateDeterministicKey();
};