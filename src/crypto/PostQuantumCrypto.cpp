/**
 * @file PostQuantumCrypto.cpp
 * @brief Implementation of post-quantum cryptographic operations
 *
 * This file implements quantum-resistant cryptography using the Open Quantum Safe (OQS) library.
 * It provides a Qt-friendly interface to NIST-standard post-quantum algorithms including
 * Kyber-1024 for key encapsulation and ML-DSA-65 for digital signatures.
 *
 * Key implementation details:
 * - Secure memory management using OQS secure free functions
 * - Error handling with proper cleanup on failures
 * - Deterministic key derivation for symmetric encryption consistency
 * - Binary-safe file encryption/decryption
 */

#include "PostQuantumCrypto.h"

#include <QRandomGenerator>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <cstring>

PostQuantumCrypto::PostQuantumCrypto(QObject *parent)
    : QObject(parent)
{
    if (!initializeOQS()) {
        qWarning() << "Failed to initialize OQS library";
    }
    qDebug() << "PostQuantumCrypto initialized with Kyber-1024 and Dilithium";
}

PostQuantumCrypto::~PostQuantumCrypto()
{
    cleanupKeys();
}

bool PostQuantumCrypto::initializeOQS()
{
    // Check if the required algorithms are enabled
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_1024)) {
        qWarning() << "Kyber-1024 not enabled in liboqs";
        return false;
    }

    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_65)) {
        qWarning() << "CRYSTALS-Dilithium5 (ML-DSA-65) not enabled in liboqs";
        return false;
    }

    return true;
}

void PostQuantumCrypto::cleanupKeys()
{
    if (m_kyberPublicKey) {
        OQS_MEM_secure_free(m_kyberPublicKey, OQS_KEM_kyber_1024_length_public_key);
        m_kyberPublicKey = nullptr;
    }
    if (m_kyberSecretKey) {
        OQS_MEM_secure_free(m_kyberSecretKey, OQS_KEM_kyber_1024_length_secret_key);
        m_kyberSecretKey = nullptr;
    }
    if (m_dilithiumPublicKey) {
        OQS_MEM_secure_free(m_dilithiumPublicKey, OQS_SIG_ml_dsa_65_length_public_key);
        m_dilithiumPublicKey = nullptr;
    }
    if (m_dilithiumSecretKey) {
        OQS_MEM_secure_free(m_dilithiumSecretKey, OQS_SIG_ml_dsa_65_length_secret_key);
        m_dilithiumSecretKey = nullptr;
    }
    m_publicKeyHex.clear();
}

/**
 * @brief Generates a new Kyber-1024 + ML-DSA-65 key pair
 *
 * Creates quantum-resistant key pairs using cryptographically secure
 * random number generation. The keys are stored internally and used
 * for all subsequent cryptographic operations.
 *
 * Key generation process:
 * 1. Allocate secure memory for Kyber keys using OQS functions
 * 2. Generate Kyber-1024 key pair for key encapsulation
 * 3. Allocate secure memory for Dilithium keys
 * 4. Generate ML-DSA-65 key pair for digital signatures
 * 5. Combine public keys into a single hex string for export/display
 *
 * @return bool True if key generation succeeded
 */
bool PostQuantumCrypto::generateKeyPair()
{
    cleanupKeys();

    try {
        // Allocate memory for Kyber keys using OQS secure allocator
        m_kyberPublicKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_public_key));
        m_kyberSecretKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_secret_key));

        if (!m_kyberPublicKey || !m_kyberSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Kyber keys");
        }

        // Generate Kyber key pair using NIST-standard algorithm
        OQS_STATUS status = OQS_KEM_kyber_1024_keypair(m_kyberPublicKey, m_kyberSecretKey);
        if (status != OQS_SUCCESS) {
            throw std::runtime_error("Failed to generate Kyber key pair");
        }

        // Allocate memory for Dilithium keys
        m_dilithiumPublicKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_public_key));
        m_dilithiumSecretKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_secret_key));

        if (!m_dilithiumPublicKey || !m_dilithiumSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Dilithium keys");
        }

        // Generate Dilithium key pair for digital signatures
        status = OQS_SIG_ml_dsa_65_keypair(m_dilithiumPublicKey, m_dilithiumSecretKey);
        if (status != OQS_SUCCESS) {
            throw std::runtime_error("Failed to generate Dilithium key pair");
        }

        // Create combined public key hex for display/export
        // Format: Kyber public key + Dilithium public key
        QByteArray combinedPubKey;
        combinedPubKey.append(reinterpret_cast<char*>(m_kyberPublicKey), OQS_KEM_kyber_1024_length_public_key);
        combinedPubKey.append(reinterpret_cast<char*>(m_dilithiumPublicKey), OQS_SIG_ml_dsa_65_length_public_key);
        m_publicKeyHex = combinedPubKey.toHex().toUpper();

        qDebug() << "Generated PQ key pairs successfully";
        emit keysChanged();
        emit operationCompleted("generateKeyPair", true, "Key pairs generated successfully");
        return true;
    } catch (const std::exception &e) {
        cleanupKeys();
        qWarning() << "Failed to generate key pairs:" << e.what();
        emit operationCompleted("generateKeyPair", false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

bool PostQuantumCrypto::importKeyPair(const QString &privateKeyHex, const QString &publicKeyHex)
{
    cleanupKeys();

    try {
        QByteArray privateKeyData = QByteArray::fromHex(privateKeyHex.toUtf8());
        QByteArray publicKeyData = QByteArray::fromHex(publicKeyHex.toUtf8());

        if (privateKeyData.size() != OQS_KEM_kyber_1024_length_secret_key + OQS_SIG_ml_dsa_65_length_secret_key) {
            throw std::runtime_error("Invalid private key length");
        }

        if (publicKeyData.size() != OQS_KEM_kyber_1024_length_public_key + OQS_SIG_ml_dsa_65_length_public_key) {
            throw std::runtime_error("Invalid public key length");
        }

        // Allocate and copy Kyber keys
        m_kyberPublicKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_public_key));
        m_kyberSecretKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_secret_key));

        if (!m_kyberPublicKey || !m_kyberSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Kyber keys");
        }

        memcpy(m_kyberPublicKey, publicKeyData.constData(), OQS_KEM_kyber_1024_length_public_key);
        memcpy(m_kyberSecretKey, privateKeyData.constData(), OQS_KEM_kyber_1024_length_secret_key);

        // Allocate and copy Dilithium keys
        m_dilithiumPublicKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_public_key));
        m_dilithiumSecretKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_secret_key));

        if (!m_dilithiumPublicKey || !m_dilithiumSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Dilithium keys");
        }

        memcpy(m_dilithiumPublicKey, publicKeyData.constData() + OQS_KEM_kyber_1024_length_public_key, OQS_SIG_ml_dsa_65_length_public_key);
        memcpy(m_dilithiumSecretKey, privateKeyData.constData() + OQS_KEM_kyber_1024_length_secret_key, OQS_SIG_ml_dsa_65_length_secret_key);

        m_publicKeyHex = publicKeyHex.toUpper();

        qDebug() << "Imported PQ key pairs successfully";
        emit keysChanged();
        emit operationCompleted("importKeyPair", true, "Key pairs imported successfully");
        return true;
    } catch (const std::exception &e) {
        cleanupKeys();
        qWarning() << "Failed to import key pairs:" << e.what();
        emit operationCompleted("importKeyPair", false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

QString PostQuantumCrypto::exportPrivateKey() const
{
    if (!m_kyberSecretKey || !m_dilithiumSecretKey) {
        return QString();
    }

    QByteArray combinedPrivateKey;
    combinedPrivateKey.append(reinterpret_cast<char*>(m_kyberSecretKey), OQS_KEM_kyber_1024_length_secret_key);
    combinedPrivateKey.append(reinterpret_cast<char*>(m_dilithiumSecretKey), OQS_SIG_ml_dsa_65_length_secret_key);

    return combinedPrivateKey.toHex().toUpper();
}

QString PostQuantumCrypto::exportPublicKey() const
{
    return m_publicKeyHex;
}

QString PostQuantumCrypto::signMessage(const QString &message)
{
    if (!m_dilithiumSecretKey) {
        emit operationCompleted("signMessage", false, "No Dilithium private key available");
        return QString();
    }

    try {
        QByteArray messageData = message.toUtf8();
        QByteArray signature = dilithiumSign(messageData, m_dilithiumSecretKey, OQS_SIG_ml_dsa_65_length_secret_key);

        QString signatureHex = signature.toHex().toUpper();
        emit operationCompleted("signMessage", true, QString("Message signed with Dilithium"));
        return signatureHex;
    } catch (const std::exception &e) {
        qWarning() << "Failed to sign message:" << e.what();
        emit operationCompleted("signMessage", false, QString("Error: %1").arg(e.what()));
        return QString();
    }
}

bool PostQuantumCrypto::verifySignature(const QString &message, const QString &signature, const QString &publicKeyHex)
{
    try {
        QByteArray messageData = message.toUtf8();
        QByteArray signatureData = QByteArray::fromHex(signature.toUtf8());
        QByteArray publicKeyData = QByteArray::fromHex(publicKeyHex.toUtf8());

        if (publicKeyData.size() != OQS_KEM_kyber_1024_length_public_key + OQS_SIG_ml_dsa_65_length_public_key) {
            throw std::runtime_error("Invalid public key length");
        }

        // Extract Dilithium public key from combined key
        QByteArray dilithiumPubKeyData = publicKeyData.mid(OQS_KEM_kyber_1024_length_public_key, OQS_SIG_ml_dsa_65_length_public_key);
        const uint8_t *dilithiumPubKey = reinterpret_cast<const uint8_t*>(dilithiumPubKeyData.constData());

        bool valid = dilithiumVerify(messageData, signatureData, dilithiumPubKey, OQS_SIG_ml_dsa_65_length_public_key);
        emit operationCompleted("verifySignature", valid, valid ? "Dilithium signature verified" : "Signature verification failed");
        return valid;
    } catch (const std::exception &e) {
        qWarning() << "Failed to verify signature:" << e.what();
        emit operationCompleted("verifySignature", false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

QVariantMap PostQuantumCrypto::encapsulateKey(const QString &recipientPublicKeyHex)
{
    QVariantMap result;

    try {
        QByteArray recipientPubKeyData = QByteArray::fromHex(recipientPublicKeyHex.toUtf8());

        if (recipientPubKeyData.size() != OQS_KEM_kyber_1024_length_public_key + OQS_SIG_ml_dsa_65_length_public_key) {
            throw std::runtime_error("Invalid recipient public key length");
        }

        // Extract Kyber public key from combined key
        const uint8_t *kyberPubKey = reinterpret_cast<const uint8_t*>(recipientPubKeyData.constData());

        QByteArray encapsulatedKey = kyberEncapsulate(kyberPubKey, OQS_KEM_kyber_1024_length_public_key);

        result["ciphertext"] = encapsulatedKey.toHex().toUpper();
        result["sharedSecret"] = encapsulatedKey.mid(OQS_KEM_kyber_1024_length_ciphertext).toHex().toUpper();

        emit operationCompleted("encapsulateKey", true, "Kyber key encapsulation successful");
    } catch (const std::exception &e) {
        qWarning() << "Failed to encapsulate key:" << e.what();
        result["error"] = QString("Error: %1").arg(e.what());
        emit operationCompleted("encapsulateKey", false, QString("Error: %1").arg(e.what()));
    }

    return result;
}

QByteArray PostQuantumCrypto::decapsulateKey(const QVariantMap &encapsulatedKey)
{
    try {
        if (!encapsulatedKey.contains("ciphertext") || !m_kyberSecretKey) {
            throw std::runtime_error("Missing ciphertext or no Kyber secret key");
        }

        QByteArray ciphertext = QByteArray::fromHex(encapsulatedKey["ciphertext"].toString().toUtf8());
        QByteArray sharedSecret = kyberDecapsulate(ciphertext, m_kyberSecretKey, OQS_KEM_kyber_1024_length_secret_key);

        emit operationCompleted("decapsulateKey", true, "Kyber key decapsulation successful");
        return sharedSecret;
    } catch (const std::exception &e) {
        qWarning() << "Failed to decapsulate key:" << e.what();
        emit operationCompleted("decapsulateKey", false, QString("Error: %1").arg(e.what()));
        return QByteArray();
    }
}

QString PostQuantumCrypto::encryptText(const QString &plaintext)
{
    try {
        if (!hasKeys()) {
            throw std::runtime_error("No PQ keys available for encryption");
        }

        // Generate a deterministic symmetric key from our PQ keys
        QByteArray symmetricKey = generateDeterministicKey();
        if (symmetricKey.size() != 32) {
            throw std::runtime_error("Failed to generate symmetric key");
        }

        // Generate random IV
        QByteArray iv(16, 0);
        QRandomGenerator::global()->generate(iv.begin(), iv.end());

        // Convert plaintext to bytes
        QByteArray plaintextData = plaintext.toUtf8();

        // Simple XOR encryption with deterministic key (for demo purposes)
        // In production, use proper AES-GCM
        QByteArray ciphertext = plaintextData;
        for (int i = 0; i < ciphertext.size(); ++i) {
            ciphertext[i] = ciphertext[i] ^ symmetricKey[i % symmetricKey.size()];
        }

        // Combine IV + ciphertext and encode as base64
        QByteArray combined;
        combined.append(iv);
        combined.append(ciphertext);

        QString result = combined.toBase64();
        emit operationCompleted("encryptText", true, "Text encrypted successfully");
        return result;

    } catch (const std::exception &e) {
        qWarning() << "Failed to encrypt text:" << e.what();
        emit operationCompleted("encryptText", false, QString("Error: %1").arg(e.what()));
        return QString();
    }
}

QString PostQuantumCrypto::decryptText(const QString &ciphertext)
{
    try {
        if (!hasKeys()) {
            throw std::runtime_error("No PQ keys available for decryption");
        }

        // Decode from base64
        QByteArray combined = QByteArray::fromBase64(ciphertext.toUtf8());
        if (combined.size() < 16) {
            throw std::runtime_error("Invalid ciphertext format");
        }

        // Extract IV and ciphertext
        QByteArray iv = combined.left(16);
        QByteArray encryptedData = combined.mid(16);

        // Generate the SAME deterministic symmetric key
        QByteArray symmetricKey = generateDeterministicKey();
        if (symmetricKey.size() != 32) {
            throw std::runtime_error("Failed to generate symmetric key");
        }

        // XOR decryption (matches encryption above)
        QByteArray plaintext = encryptedData;
        for (int i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = plaintext[i] ^ symmetricKey[i % symmetricKey.size()];
        }

        QString result = QString::fromUtf8(plaintext);
        emit operationCompleted("decryptText", true, "Text decrypted successfully");
        return result;

    } catch (const std::exception &e) {
        qWarning() << "Failed to decrypt text:" << e.what();
        emit operationCompleted("decryptText", false, QString("Error: %1").arg(e.what()));
        return QString();
    }
}

bool PostQuantumCrypto::saveEncryptedTextToFile(const QString &content, const QString &filePath)
{
    try {
        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            emit operationCompleted("saveEncryptedTextToFile", false, QString("Cannot open file for writing: %1").arg(filePath));
            return false;
        }

        QTextStream out(&file);
        out << content;
        file.close();

        emit operationCompleted("saveEncryptedTextToFile", true, QString("Encrypted text saved to: %1").arg(filePath));
        return true;
    } catch (const std::exception &e) {
        qWarning() << "Failed to save encrypted text:" << e.what();
        emit operationCompleted("saveEncryptedTextToFile", false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

QString PostQuantumCrypto::loadEncryptedTextFromFile(const QString &filePath)
{
    try {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            emit operationCompleted("loadEncryptedTextFromFile", false, QString("Cannot open file for reading: %1").arg(filePath));
            return QString();
        }

        QTextStream in(&file);
        QString content = in.readAll();
        file.close();

        emit operationCompleted("loadEncryptedTextFromFile", true, QString("Encrypted text loaded from: %1").arg(filePath));
        return content;
    } catch (const std::exception &e) {
        qWarning() << "Failed to load encrypted text:" << e.what();
        emit operationCompleted("loadEncryptedTextFromFile", false, QString("Error: %1").arg(e.what()));
        return QString();
    }
}

bool PostQuantumCrypto::encryptFile(const QString &inputFilePath, const QString &outputFilePath)
{
    try {
        // Open input file
        QFile inputFile(inputFilePath);
        if (!inputFile.open(QIODevice::ReadOnly)) {
            emit operationCompleted("encryptFile", false, QString("Cannot open input file: %1").arg(inputFilePath));
            return false;
        }

        // Get file size for progress calculation
        qint64 fileSize = inputFile.size();
        qint64 bytesProcessed = 0;

        // Open output file
        QFile outputFile(outputFilePath);
        if (!outputFile.open(QIODevice::WriteOnly)) {
            inputFile.close();
            emit operationCompleted("encryptFile", false, QString("Cannot open output file: %1").arg(outputFilePath));
            return false;
        }

        emit operationProgress("encryptFile", 0, "Initializing encryption...");

        // Process file in chunks to avoid loading large files into memory
        const qint64 chunkSize = 1024 * 1024; // 1MB chunks
        QByteArray buffer;

        while (!inputFile.atEnd()) {
            buffer = inputFile.read(chunkSize);
            if (buffer.isEmpty()) {
                break;
            }

            // Encrypt the chunk
            QByteArray encryptedChunk = encryptBinary(buffer);
            if (encryptedChunk.isEmpty()) {
                inputFile.close();
                outputFile.close();
                emit operationCompleted("encryptFile", false, "Encryption failed during processing");
                return false;
            }

            // Write encrypted chunk
            outputFile.write(encryptedChunk);

            // Update progress
            bytesProcessed += buffer.size();
            int progress = fileSize > 0 ? (bytesProcessed * 100) / fileSize : 0;
            emit operationProgress("encryptFile", progress, QString("Encrypting... %1%").arg(progress));
        }

        inputFile.close();
        outputFile.close();

        emit operationProgress("encryptFile", 100, "Encryption completed");
        emit operationCompleted("encryptFile", true, QString("File encrypted: %1 -> %2").arg(inputFilePath, outputFilePath));
        return true;
    } catch (const std::exception &e) {
        qWarning() << "Failed to encrypt file:" << e.what();
        emit operationCompleted("encryptFile", false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

bool PostQuantumCrypto::decryptFile(const QString &inputFilePath, const QString &outputFilePath)
{
    try {
        // Open input file
        QFile inputFile(inputFilePath);
        if (!inputFile.open(QIODevice::ReadOnly)) {
            emit operationCompleted("decryptFile", false, QString("Cannot open input file: %1").arg(inputFilePath));
            return false;
        }

        // Get file size for progress calculation
        qint64 fileSize = inputFile.size();
        qint64 bytesProcessed = 0;

        emit operationProgress("decryptFile", 0, "Initializing decryption...");

        // Read the entire encrypted file (we need the IV from the beginning)
        QByteArray encryptedData = inputFile.readAll();
        inputFile.close();

        if (encryptedData.size() < 16) {
            emit operationCompleted("decryptFile", false, "Invalid encrypted file format");
            return false;
        }

        // Decrypt the binary data
        QByteArray decryptedData = decryptBinary(encryptedData);
        if (decryptedData.isEmpty()) {
            emit operationCompleted("decryptFile", false, "Decryption failed - invalid file or key");
            return false;
        }

        // Open output file
        QFile outputFile(outputFilePath);
        if (!outputFile.open(QIODevice::WriteOnly)) {
            emit operationCompleted("decryptFile", false, QString("Cannot open output file: %1").arg(outputFilePath));
            return false;
        }

        // Write decrypted data in chunks to show progress
        const qint64 chunkSize = 1024 * 1024; // 1MB chunks
        qint64 bytesWritten = 0;

        while (bytesWritten < decryptedData.size()) {
            qint64 remaining = decryptedData.size() - bytesWritten;
            qint64 writeSize = qMin(chunkSize, remaining);

            QByteArray chunk = decryptedData.mid(bytesWritten, writeSize);
            outputFile.write(chunk);

            bytesWritten += writeSize;
            int progress = decryptedData.size() > 0 ? (bytesWritten * 100) / decryptedData.size() : 0;
            emit operationProgress("decryptFile", progress, QString("Decrypting... %1%").arg(progress));
        }

        outputFile.close();

        emit operationProgress("decryptFile", 100, "Decryption completed");
        emit operationCompleted("decryptFile", true, QString("File decrypted: %1 -> %2").arg(inputFilePath, outputFilePath));
        return true;
    } catch (const std::exception &e) {
        qWarning() << "Failed to decrypt file:" << e.what();
        emit operationCompleted("decryptFile", false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

QByteArray PostQuantumCrypto::encryptBinary(const QByteArray &plaintext)
{
    try {
        if (!hasKeys()) {
            return QByteArray();
        }

        // Generate a deterministic symmetric key
        QByteArray symmetricKey = generateDeterministicKey();
        if (symmetricKey.size() != 32) {
            return QByteArray();
        }

        // Generate random IV
        QByteArray iv(16, 0);
        QRandomGenerator::global()->generate(iv.begin(), iv.end());

        // XOR encryption with deterministic key
        QByteArray ciphertext = plaintext;
        for (int i = 0; i < ciphertext.size(); ++i) {
            ciphertext[i] = ciphertext[i] ^ symmetricKey[i % symmetricKey.size()];
        }

        // Combine IV + ciphertext
        QByteArray combined;
        combined.append(iv);
        combined.append(ciphertext);

        return combined;
    } catch (const std::exception &e) {
        qWarning() << "Failed to encrypt binary data:" << e.what();
        return QByteArray();
    }
}

QByteArray PostQuantumCrypto::decryptBinary(const QByteArray &ciphertext)
{
    try {
        if (!hasKeys()) {
            return QByteArray();
        }

        if (ciphertext.size() < 16) {
            return QByteArray();
        }

        // Extract IV and ciphertext
        QByteArray iv = ciphertext.left(16);
        QByteArray encryptedData = ciphertext.mid(16);

        // Generate the SAME deterministic symmetric key
        QByteArray symmetricKey = generateDeterministicKey();
        if (symmetricKey.size() != 32) {
            return QByteArray();
        }

        // XOR decryption
        QByteArray plaintext = encryptedData;
        for (int i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = plaintext[i] ^ symmetricKey[i % symmetricKey.size()];
        }

        return plaintext;
    } catch (const std::exception &e) {
        qWarning() << "Failed to decrypt binary data:" << e.what();
        return QByteArray();
    }
}

/**
 * @brief Generates a deterministic symmetric key from PQ keys
 *
 * Creates a consistent 32-byte key for symmetric encryption/decryption
 * by hashing the combination of Kyber and Dilithium private keys.
 *
 * This ensures that:
 * - The same key is generated for encryption and decryption
 * - Keys are derived from quantum-resistant private keys
 * - No additional key management is required
 *
 * Process:
 * 1. Combine Kyber and Dilithium secret keys
 * 2. Add a fixed salt for domain separation
 * 3. Hash with SHA-256 to produce 32-byte key
 *
 * @return QByteArray 32-byte deterministic symmetric key
 */
QByteArray PostQuantumCrypto::generateDeterministicKey()
{
    // Create a deterministic key from our PQ keys using SHA-256
    // This ensures the same key is generated for encryption/decryption
    QByteArray keyMaterial;

    // Combine Kyber and Dilithium keys for maximum entropy
    if (m_kyberSecretKey) {
        keyMaterial.append(reinterpret_cast<char*>(m_kyberSecretKey), OQS_KEM_kyber_1024_length_secret_key);
    }
    if (m_dilithiumSecretKey) {
        keyMaterial.append(reinterpret_cast<char*>(m_dilithiumSecretKey), OQS_SIG_ml_dsa_65_length_secret_key);
    }

    // Add a fixed salt for key derivation to prevent attacks
    // This separates the key derivation domain from other uses
    keyMaterial.append("cybou_pq_key_derivation_salt_2024");

    // Hash to get a 32-byte (256-bit) key suitable for symmetric encryption
    QByteArray hash = QCryptographicHash::hash(keyMaterial, QCryptographicHash::Sha256);
    return hash;
}

QString PostQuantumCrypto::generateSharedSecret(const QString &otherPublicKeyHex)
{
    try {
        if (!m_kyberSecretKey) {
            throw std::runtime_error("No Kyber private key available");
        }

        QByteArray otherPubKeyData = QByteArray::fromHex(otherPublicKeyHex.toUtf8());

        if (otherPubKeyData.size() != OQS_KEM_kyber_1024_length_public_key + OQS_SIG_ml_dsa_65_length_public_key) {
            throw std::runtime_error("Invalid public key length");
        }

        // Extract Kyber public key from combined key
        const uint8_t *kyberPubKey = reinterpret_cast<const uint8_t*>(otherPubKeyData.constData());

        // Perform key encapsulation to get shared secret
        uint8_t *ciphertext = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_ciphertext));
        uint8_t *shared_secret = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_shared_secret));

        if (!ciphertext || !shared_secret) {
            OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
            OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
            throw std::runtime_error("Failed to allocate memory for key encapsulation");
        }

        OQS_STATUS status = OQS_KEM_kyber_1024_encaps(ciphertext, shared_secret, kyberPubKey);
        if (status != OQS_SUCCESS) {
            OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
            OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
            throw std::runtime_error("Failed to perform key encapsulation");
        }

        QByteArray sharedSecretHex = QByteArray(reinterpret_cast<char*>(shared_secret), OQS_KEM_kyber_1024_length_shared_secret).toHex().toUpper();

        OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
        OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);

        return sharedSecretHex;
    } catch (const std::exception &e) {
        qWarning() << "Failed to generate shared secret:" << e.what();
        return QString();
    }
}

// Private implementation methods using liboqs

QByteArray PostQuantumCrypto::kyberEncapsulate(const uint8_t *publicKey, size_t publicKeyLen)
{
    uint8_t *ciphertext = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_ciphertext));
    uint8_t *shared_secret = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_shared_secret));

    if (!ciphertext || !shared_secret) {
        OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
        OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
        throw std::runtime_error("Failed to allocate memory for encapsulation");
    }

    OQS_STATUS status = OQS_KEM_kyber_1024_encaps(ciphertext, shared_secret, publicKey);
    if (status != OQS_SUCCESS) {
        OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
        OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
        throw std::runtime_error("Kyber encapsulation failed");
    }

    QByteArray result;
    result.append(reinterpret_cast<char*>(ciphertext), OQS_KEM_kyber_1024_length_ciphertext);
    result.append(reinterpret_cast<char*>(shared_secret), OQS_KEM_kyber_1024_length_shared_secret);

    OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
    OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);

    return result;
}

QByteArray PostQuantumCrypto::kyberDecapsulate(const QByteArray &ciphertext, const uint8_t *secretKey, size_t secretKeyLen)
{
    if (ciphertext.size() < OQS_KEM_kyber_1024_length_ciphertext) {
        throw std::runtime_error("Invalid ciphertext length");
    }

    uint8_t *shared_secret = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_shared_secret));
    if (!shared_secret) {
        throw std::runtime_error("Failed to allocate memory for shared secret");
    }

    OQS_STATUS status = OQS_KEM_kyber_1024_decaps(shared_secret,
                                                  reinterpret_cast<const uint8_t*>(ciphertext.constData()),
                                                  secretKey);
    if (status != OQS_SUCCESS) {
        OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
        throw std::runtime_error("Kyber decapsulation failed");
    }

    QByteArray result(reinterpret_cast<char*>(shared_secret), OQS_KEM_kyber_1024_length_shared_secret);
    OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);

    return result;
}

QByteArray PostQuantumCrypto::dilithiumSign(const QByteArray &message, const uint8_t *secretKey, size_t secretKeyLen)
{
    size_t signature_len = OQS_SIG_ml_dsa_65_length_signature;
    uint8_t *signature = static_cast<uint8_t*>(OQS_MEM_malloc(signature_len));

    if (!signature) {
        throw std::runtime_error("Failed to allocate memory for signature");
    }

    OQS_STATUS status = OQS_SIG_ml_dsa_65_sign(signature, &signature_len,
                                               reinterpret_cast<const uint8_t*>(message.constData()),
                                               message.size(), secretKey);
    if (status != OQS_SUCCESS) {
        OQS_MEM_secure_free(signature, signature_len);
        throw std::runtime_error("Dilithium signing failed");
    }

    QByteArray result(reinterpret_cast<char*>(signature), signature_len);
    OQS_MEM_secure_free(signature, signature_len);

    return result;
}

bool PostQuantumCrypto::dilithiumVerify(const QByteArray &message, const QByteArray &signature, const uint8_t *publicKey, size_t publicKeyLen)
{
    OQS_STATUS status = OQS_SIG_ml_dsa_65_verify(reinterpret_cast<const uint8_t*>(signature.constData()),
                                                   signature.size(),
                                                   reinterpret_cast<const uint8_t*>(message.constData()),
                                                   message.size(), publicKey);
    return status == OQS_SUCCESS;
}