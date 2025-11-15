/**
 * @file SignatureEngine.cpp
 * @brief Implementation of digital signature and key exchange operations
 *
 * This module handles ML-DSA-65 digital signatures and Kyber-1024
 * key encapsulation for quantum-resistant key exchange.
 */

#include "SignatureEngine.h"
#include "KeyManager.h"
#include <QDebug>
#include <stdexcept>

extern "C" {
#include <oqs/oqs.h>
}

/**
 * @brief Constructs a SignatureEngine instance
 * @param keyManager Pointer to KeyManager for key access
 * @param parent Parent QObject for Qt memory management
 */
SignatureEngine::SignatureEngine(KeyManager *keyManager, QObject *parent)
    : QObject(parent)
    , m_keyManager(keyManager)
{
    if (!m_keyManager) {
        qWarning() << "SignatureEngine: KeyManager is null!";
    }
    qDebug() << "SignatureEngine initialized";
}

/**
 * @brief Signs a message with ML-DSA-65
 * 
 * Creates a quantum-resistant digital signature using the
 * Dilithium secret key stored in KeyManager.
 *
 * @param message Text message to sign
 * @return QString Hex-encoded signature, empty on failure
 * @emits signatureCreated() on success
 * @emits signatureOperationFailed() on failure
 */
QString SignatureEngine::signMessage(const QString &message)
{
    if (!m_keyManager || !m_keyManager->hasKeys()) {
        emit signatureOperationFailed("No Dilithium private key available");
        return QString();
    }
    
    try {
        const uint8_t *dilithiumSecretKey = m_keyManager->getDilithiumSecretKey();
        if (!dilithiumSecretKey) {
            throw std::runtime_error("Dilithium secret key not available");
        }
        
        QByteArray messageData = message.toUtf8();
        
        // Allocate memory for signature
        size_t signature_len = OQS_SIG_ml_dsa_65_length_signature;
        uint8_t *signature = static_cast<uint8_t*>(OQS_MEM_malloc(signature_len));
        
        if (!signature) {
            throw std::runtime_error("Failed to allocate memory for signature");
        }
        
        // Sign the message with ML-DSA-65
        OQS_STATUS status = OQS_SIG_ml_dsa_65_sign(
            signature,
            &signature_len,
            reinterpret_cast<const uint8_t*>(messageData.constData()),
            messageData.size(),
            dilithiumSecretKey
        );
        
        if (status != OQS_SUCCESS) {
            OQS_MEM_secure_free(signature, signature_len);
            throw std::runtime_error("ML-DSA-65 signing failed");
        }
        
        // Convert signature to hex
        QByteArray signatureData(reinterpret_cast<char*>(signature), signature_len);
        QString signatureHex = signatureData.toHex().toUpper();
        
        OQS_MEM_secure_free(signature, signature_len);
        
        qDebug() << "SignatureEngine: Message signed successfully";
        emit signatureCreated(signatureHex);
        return signatureHex;
        
    } catch (const std::exception &e) {
        qWarning() << "SignatureEngine: Failed to sign message:" << e.what();
        emit signatureOperationFailed(QString("Signing failed: %1").arg(e.what()));
        return QString();
    }
}

/**
 * @brief Verifies a message signature with ML-DSA-65
 * 
 * Validates a digital signature against a message and public key.
 *
 * @param message Original text message
 * @param signatureHex Hex-encoded signature to verify
 * @param publicKeyHex Hex-encoded combined public key (Kyber + Dilithium)
 * @return bool True if signature is valid, false otherwise
 * @emits signatureVerified() on success
 * @emits signatureOperationFailed() on verification failure
 */
bool SignatureEngine::verifySignature(const QString &message,
                                      const QString &signatureHex,
                                      const QString &publicKeyHex)
{
    try {
        QByteArray messageData = message.toUtf8();
        QByteArray signatureData = QByteArray::fromHex(signatureHex.toUtf8());
        QByteArray publicKeyData = QByteArray::fromHex(publicKeyHex.toUtf8());
        
        // Validate combined public key length
        const int expectedKeyLength = OQS_KEM_kyber_1024_length_public_key + 
                                     OQS_SIG_ml_dsa_65_length_public_key;
        if (publicKeyData.size() != expectedKeyLength) {
            throw std::runtime_error("Invalid public key length");
        }
        
        // Extract Dilithium public key from combined key
        // Format: [Kyber Public Key][Dilithium Public Key]
        QByteArray dilithiumPubKeyData = publicKeyData.mid(
            OQS_KEM_kyber_1024_length_public_key,
            OQS_SIG_ml_dsa_65_length_public_key
        );
        const uint8_t *dilithiumPubKey = reinterpret_cast<const uint8_t*>(
            dilithiumPubKeyData.constData()
        );
        
        // Verify the signature
        OQS_STATUS status = OQS_SIG_ml_dsa_65_verify(
            reinterpret_cast<const uint8_t*>(signatureData.constData()),
            signatureData.size(),
            reinterpret_cast<const uint8_t*>(messageData.constData()),
            messageData.size(),
            dilithiumPubKey
        );
        
        bool valid = (status == OQS_SUCCESS);
        
        if (valid) {
            qDebug() << "SignatureEngine: Signature verified successfully";
            emit signatureVerified(true, "ML-DSA-65 signature verified");
        } else {
            qDebug() << "SignatureEngine: Signature verification failed";
            emit signatureVerified(false, "Signature verification failed");
        }
        
        return valid;
        
    } catch (const std::exception &e) {
        qWarning() << "SignatureEngine: Failed to verify signature:" << e.what();
        emit signatureOperationFailed(QString("Verification failed: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Encapsulates a shared secret with Kyber-1024
 * 
 * Performs key encapsulation to establish a shared secret with
 * a recipient's public key. Returns both the ciphertext and
 * the shared secret.
 *
 * @param recipientPublicKeyHex Hex-encoded combined public key
 * @return QVariantMap Contains "ciphertext" and "sharedSecret" keys
 * @emits keyEncapsulated() on success
 * @emits signatureOperationFailed() on failure
 */
QVariantMap SignatureEngine::encapsulateKey(const QString &recipientPublicKeyHex)
{
    QVariantMap result;
    
    try {
        QByteArray recipientPubKeyData = QByteArray::fromHex(recipientPublicKeyHex.toUtf8());
        
        // Validate combined public key length
        const int expectedKeyLength = OQS_KEM_kyber_1024_length_public_key + 
                                     OQS_SIG_ml_dsa_65_length_public_key;
        if (recipientPubKeyData.size() != expectedKeyLength) {
            throw std::runtime_error("Invalid recipient public key length");
        }
        
        // Extract Kyber public key from combined key
        // Format: [Kyber Public Key][Dilithium Public Key]
        const uint8_t *kyberPubKey = reinterpret_cast<const uint8_t*>(
            recipientPubKeyData.constData()
        );
        
        // Allocate memory for encapsulation
        uint8_t *ciphertext = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_ciphertext)
        );
        uint8_t *shared_secret = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_shared_secret)
        );
        
        if (!ciphertext || !shared_secret) {
            OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
            OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
            throw std::runtime_error("Failed to allocate memory for encapsulation");
        }
        
        // Perform Kyber encapsulation
        OQS_STATUS status = OQS_KEM_kyber_1024_encaps(
            ciphertext,
            shared_secret,
            kyberPubKey
        );
        
        if (status != OQS_SUCCESS) {
            OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
            OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
            throw std::runtime_error("Kyber encapsulation failed");
        }
        
        // Convert to hex strings
        QByteArray ciphertextData(
            reinterpret_cast<char*>(ciphertext),
            OQS_KEM_kyber_1024_length_ciphertext
        );
        QByteArray sharedSecretData(
            reinterpret_cast<char*>(shared_secret),
            OQS_KEM_kyber_1024_length_shared_secret
        );
        
        result["ciphertext"] = ciphertextData.toHex().toUpper();
        result["sharedSecret"] = sharedSecretData.toHex().toUpper();
        
        OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
        OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
        
        qDebug() << "SignatureEngine: Key encapsulation successful";
        emit keyEncapsulated(result["ciphertext"].toString(), result["sharedSecret"].toString());
        
    } catch (const std::exception &e) {
        qWarning() << "SignatureEngine: Failed to encapsulate key:" << e.what();
        result["error"] = QString("Error: %1").arg(e.what());
        emit signatureOperationFailed(QString("Encapsulation failed: %1").arg(e.what()));
    }
    
    return result;
}

/**
 * @brief Decapsulates a shared secret with Kyber-1024
 * 
 * Recovers the shared secret from a ciphertext using the
 * local Kyber secret key.
 *
 * @param ciphertextHex Hex-encoded Kyber ciphertext
 * @return QByteArray Shared secret bytes, empty on failure
 * @emits keyDecapsulated() on success
 * @emits signatureOperationFailed() on failure
 */
QByteArray SignatureEngine::decapsulateKey(const QString &ciphertextHex)
{
    if (!m_keyManager || !m_keyManager->hasKeys()) {
        emit signatureOperationFailed("No Kyber private key available");
        return QByteArray();
    }
    
    try {
        const uint8_t *kyberSecretKey = m_keyManager->getKyberSecretKey();
        if (!kyberSecretKey) {
            throw std::runtime_error("Kyber secret key not available");
        }
        
        QByteArray ciphertext = QByteArray::fromHex(ciphertextHex.toUtf8());
        
        if (ciphertext.size() != static_cast<int>(OQS_KEM_kyber_1024_length_ciphertext)) {
            throw std::runtime_error("Invalid ciphertext length");
        }
        
        // Allocate memory for shared secret
        uint8_t *shared_secret = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_shared_secret)
        );
        
        if (!shared_secret) {
            throw std::runtime_error("Failed to allocate memory for shared secret");
        }
        
        // Perform Kyber decapsulation
        OQS_STATUS status = OQS_KEM_kyber_1024_decaps(
            shared_secret,
            reinterpret_cast<const uint8_t*>(ciphertext.constData()),
            kyberSecretKey
        );
        
        if (status != OQS_SUCCESS) {
            OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
            throw std::runtime_error("Kyber decapsulation failed");
        }
        
        QByteArray sharedSecretData(
            reinterpret_cast<char*>(shared_secret),
            OQS_KEM_kyber_1024_length_shared_secret
        );
        
        OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
        
        qDebug() << "SignatureEngine: Key decapsulation successful";
        emit keyDecapsulated(sharedSecretData);
        return sharedSecretData;
        
    } catch (const std::exception &e) {
        qWarning() << "SignatureEngine: Failed to decapsulate key:" << e.what();
        emit signatureOperationFailed(QString("Decapsulation failed: %1").arg(e.what()));
        return QByteArray();
    }
}

/**
 * @brief Generates a shared secret with another party's public key
 * 
 * Performs Kyber encapsulation to establish a shared secret.
 * This is a convenience method that wraps encapsulateKey().
 *
 * @param recipientPublicKeyHex Hex-encoded combined public key
 * @return QString Hex-encoded shared secret, empty on failure
 */
QString SignatureEngine::generateSharedSecret(const QString &recipientPublicKeyHex)
{
    try {
        if (!m_keyManager || !m_keyManager->hasKeys()) {
            throw std::runtime_error("No Kyber private key available");
        }
        
        QByteArray otherPubKeyData = QByteArray::fromHex(recipientPublicKeyHex.toUtf8());
        
        // Validate combined public key length
        const int expectedKeyLength = OQS_KEM_kyber_1024_length_public_key + 
                                     OQS_SIG_ml_dsa_65_length_public_key;
        if (otherPubKeyData.size() != expectedKeyLength) {
            throw std::runtime_error("Invalid public key length");
        }
        
        // Extract Kyber public key from combined key
        const uint8_t *kyberPubKey = reinterpret_cast<const uint8_t*>(
            otherPubKeyData.constData()
        );
        
        // Allocate memory for encapsulation
        uint8_t *ciphertext = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_ciphertext)
        );
        uint8_t *shared_secret = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_shared_secret)
        );
        
        if (!ciphertext || !shared_secret) {
            OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
            OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
            throw std::runtime_error("Failed to allocate memory for key encapsulation");
        }
        
        // Perform Kyber encapsulation
        OQS_STATUS status = OQS_KEM_kyber_1024_encaps(
            ciphertext,
            shared_secret,
            kyberPubKey
        );
        
        if (status != OQS_SUCCESS) {
            OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
            OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
            throw std::runtime_error("Failed to perform key encapsulation");
        }
        
        QByteArray sharedSecretHex = QByteArray(
            reinterpret_cast<char*>(shared_secret),
            OQS_KEM_kyber_1024_length_shared_secret
        ).toHex().toUpper();
        
        OQS_MEM_secure_free(ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
        OQS_MEM_secure_free(shared_secret, OQS_KEM_kyber_1024_length_shared_secret);
        
        qDebug() << "SignatureEngine: Shared secret generated successfully";
        return sharedSecretHex;
        
    } catch (const std::exception &e) {
        qWarning() << "SignatureEngine: Failed to generate shared secret:" << e.what();
        emit signatureOperationFailed(QString("Shared secret generation failed: %1").arg(e.what()));
        return QString();
    }
}
