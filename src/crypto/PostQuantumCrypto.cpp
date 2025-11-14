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

bool PostQuantumCrypto::generateKeyPair()
{
    cleanupKeys();

    try {
        // Allocate memory for Kyber keys
        m_kyberPublicKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_public_key));
        m_kyberSecretKey = static_cast<uint8_t*>(OQS_MEM_malloc(OQS_KEM_kyber_1024_length_secret_key));

        if (!m_kyberPublicKey || !m_kyberSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Kyber keys");
        }

        // Generate Kyber key pair
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

        // Generate Dilithium key pair
        status = OQS_SIG_ml_dsa_65_keypair(m_dilithiumPublicKey, m_dilithiumSecretKey);
        if (status != OQS_SUCCESS) {
            throw std::runtime_error("Failed to generate Dilithium key pair");
        }

        // Create combined public key hex for display
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
        const uint8_t *dilithiumPubKey = reinterpret_cast<const uint8_t*>(
            publicKeyData.constData() + OQS_KEM_kyber_1024_length_public_key);

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
        // Read input file
        QFile inputFile(inputFilePath);
        if (!inputFile.open(QIODevice::ReadOnly)) {
            emit operationCompleted("encryptFile", false, QString("Cannot open input file: %1").arg(inputFilePath));
            return false;
        }

        QByteArray fileData = inputFile.readAll();
        inputFile.close();

        // Encrypt the file data
        QString encryptedData = encryptText(QString::fromUtf8(fileData));

        // Write encrypted data to output file
        QFile outputFile(outputFilePath);
        if (!outputFile.open(QIODevice::WriteOnly)) {
            emit operationCompleted("encryptFile", false, QString("Cannot open output file: %1").arg(outputFilePath));
            return false;
        }

        QTextStream out(&outputFile);
        out << encryptedData;
        outputFile.close();

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
        // Read encrypted file
        QFile inputFile(inputFilePath);
        if (!inputFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            emit operationCompleted("decryptFile", false, QString("Cannot open input file: %1").arg(inputFilePath));
            return false;
        }

        QTextStream in(&inputFile);
        QString encryptedData = in.readAll();
        inputFile.close();

        // Decrypt the data
        QString decryptedData = decryptText(encryptedData);
        if (decryptedData.isEmpty()) {
            emit operationCompleted("decryptFile", false, "Decryption failed - invalid file or key");
            return false;
        }

        // Write decrypted data to output file
        QFile outputFile(outputFilePath);
        if (!outputFile.open(QIODevice::WriteOnly)) {
            emit operationCompleted("decryptFile", false, QString("Cannot open output file: %1").arg(outputFilePath));
            return false;
        }

        outputFile.write(decryptedData.toUtf8());
        outputFile.close();

        emit operationCompleted("decryptFile", true, QString("File decrypted: %1 -> %2").arg(inputFilePath, outputFilePath));
        return true;
    } catch (const std::exception &e) {
        qWarning() << "Failed to decrypt file:" << e.what();
        emit operationCompleted("decryptFile", false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

    return result;
}

QByteArray PostQuantumCrypto::generateDeterministicKey()
{
    // Create a deterministic key from our PQ keys using SHA-256
    // This ensures the same key is generated for encryption/decryption
    QByteArray keyMaterial;

    // Combine Kyber and Dilithium keys
    if (m_kyberSecretKey) {
        keyMaterial.append(reinterpret_cast<char*>(m_kyberSecretKey), OQS_KEM_kyber_1024_length_secret_key);
    }
    if (m_dilithiumSecretKey) {
        keyMaterial.append(reinterpret_cast<char*>(m_dilithiumSecretKey), OQS_SIG_ml_dsa_65_length_secret_key);
    }

    // Add a fixed salt for key derivation
    keyMaterial.append("cybou_pq_key_derivation_salt_2024");

    // Hash to get a 32-byte key
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