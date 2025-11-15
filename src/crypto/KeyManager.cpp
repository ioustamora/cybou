/**
 * @file KeyManager.cpp
 * @brief Implementation of post-quantum key management operations
 *
 * This module handles the lifecycle of Kyber-1024 and ML-DSA-65 key pairs,
 * including generation, secure storage, import/export, and key derivation.
 * All key material is managed using OQS secure memory allocators.
 */

#include "KeyManager.h"
#include <QCryptographicHash>
#include <QDebug>
#include <cstring>
#include <stdexcept>

/**
 * @brief Constructs a KeyManager instance
 * @param parent Parent QObject for Qt memory management
 */
KeyManager::KeyManager(QObject *parent)
    : QObject(parent)
    , m_kyberPublicKey(nullptr)
    , m_kyberSecretKey(nullptr)
    , m_dilithiumPublicKey(nullptr)
    , m_dilithiumSecretKey(nullptr)
{
    // Verify that required algorithms are available in liboqs
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_1024)) {
        qWarning() << "KeyManager: Kyber-1024 not enabled in liboqs";
    }
    
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_65)) {
        qWarning() << "KeyManager: ML-DSA-65 not enabled in liboqs";
    }
    
    qDebug() << "KeyManager initialized";
}

/**
 * @brief Destructor - securely wipes all key material
 */
KeyManager::~KeyManager()
{
    cleanupKeys();
}

/**
 * @brief Generates a new Kyber-1024 + ML-DSA-65 key pair
 * 
 * Creates quantum-resistant key pairs using cryptographically secure
 * random number generation. The keys are stored internally and used
 * for all subsequent cryptographic operations.
 *
 * Key generation process:
 * 1. Clean up any existing keys
 * 2. Allocate secure memory for Kyber keys using OQS functions
 * 3. Generate Kyber-1024 key pair for key encapsulation
 * 4. Allocate secure memory for Dilithium keys
 * 5. Generate ML-DSA-65 key pair for digital signatures
 * 6. Combine public keys into a single hex string for export/display
 *
 * @return bool True if key generation succeeded, false otherwise
 * @emits keysGenerated() on success
 * @emits keyOperationFailed() on failure
 */
bool KeyManager::generateKeyPair()
{
    cleanupKeys();
    
    try {
        // Allocate memory for Kyber keys using OQS secure allocator
        m_kyberPublicKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_public_key)
        );
        m_kyberSecretKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_secret_key)
        );
        
        if (!m_kyberPublicKey || !m_kyberSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Kyber keys");
        }
        
        // Generate Kyber key pair using NIST-standard algorithm
        OQS_STATUS status = OQS_KEM_kyber_1024_keypair(m_kyberPublicKey, m_kyberSecretKey);
        if (status != OQS_SUCCESS) {
            throw std::runtime_error("Failed to generate Kyber key pair");
        }
        
        qDebug() << "KeyManager: Kyber-1024 key pair generated successfully";
        
        // Allocate memory for Dilithium keys
        m_dilithiumPublicKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_public_key)
        );
        m_dilithiumSecretKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_secret_key)
        );
        
        if (!m_dilithiumPublicKey || !m_dilithiumSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Dilithium keys");
        }
        
        // Generate ML-DSA-65 key pair for digital signatures
        status = OQS_SIG_ml_dsa_65_keypair(m_dilithiumPublicKey, m_dilithiumSecretKey);
        if (status != OQS_SUCCESS) {
            throw std::runtime_error("Failed to generate ML-DSA-65 key pair");
        }
        
        qDebug() << "KeyManager: ML-DSA-65 key pair generated successfully";
        
        // Create combined public key hex for display/export
        // Format: Kyber public key + Dilithium public key
        QByteArray combinedPubKey;
        combinedPubKey.append(
            reinterpret_cast<char*>(m_kyberPublicKey),
            OQS_KEM_kyber_1024_length_public_key
        );
        combinedPubKey.append(
            reinterpret_cast<char*>(m_dilithiumPublicKey),
            OQS_SIG_ml_dsa_65_length_public_key
        );
        m_publicKeyHex = combinedPubKey.toHex().toUpper();
        
        emit keysGenerated();
        return true;
        
    } catch (const std::exception &e) {
        cleanupKeys();
        qWarning() << "KeyManager: Failed to generate key pairs:" << e.what();
        emit keyOperationFailed(QString("Key generation failed: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Imports a key pair from hex-encoded strings
 * 
 * Loads previously exported keys back into the KeyManager. The keys must
 * be in the exact format produced by the export methods.
 *
 * @param kyberPrivateKeyHex Hex-encoded Kyber-1024 secret key
 * @param kyberPublicKeyHex Hex-encoded Kyber-1024 public key
 * @param dilithiumPrivateKeyHex Hex-encoded ML-DSA-65 secret key
 * @param dilithiumPublicKeyHex Hex-encoded ML-DSA-65 public key
 * @return bool True if import succeeded, false if validation failed
 * @emits keysGenerated() on success
 * @emits keyOperationFailed() on failure
 */
bool KeyManager::importKeyPair(const QString &kyberPrivateKeyHex,
                                const QString &kyberPublicKeyHex,
                                const QString &dilithiumPrivateKeyHex,
                                const QString &dilithiumPublicKeyHex)
{
    cleanupKeys();
    
    try {
        // Decode Kyber keys from hex
        QByteArray kyberPrivData = QByteArray::fromHex(kyberPrivateKeyHex.toUtf8());
        QByteArray kyberPubData = QByteArray::fromHex(kyberPublicKeyHex.toUtf8());
        
        // Validate Kyber key lengths
        if (kyberPrivData.size() != static_cast<int>(OQS_KEM_kyber_1024_length_secret_key)) {
            throw std::runtime_error("Invalid Kyber private key length");
        }
        if (kyberPubData.size() != static_cast<int>(OQS_KEM_kyber_1024_length_public_key)) {
            throw std::runtime_error("Invalid Kyber public key length");
        }
        
        // Decode Dilithium keys from hex
        QByteArray dilithiumPrivData = QByteArray::fromHex(dilithiumPrivateKeyHex.toUtf8());
        QByteArray dilithiumPubData = QByteArray::fromHex(dilithiumPublicKeyHex.toUtf8());
        
        // Validate Dilithium key lengths
        if (dilithiumPrivData.size() != static_cast<int>(OQS_SIG_ml_dsa_65_length_secret_key)) {
            throw std::runtime_error("Invalid Dilithium private key length");
        }
        if (dilithiumPubData.size() != static_cast<int>(OQS_SIG_ml_dsa_65_length_public_key)) {
            throw std::runtime_error("Invalid Dilithium public key length");
        }
        
        // Allocate and copy Kyber keys
        m_kyberPublicKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_public_key)
        );
        m_kyberSecretKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_KEM_kyber_1024_length_secret_key)
        );
        
        if (!m_kyberPublicKey || !m_kyberSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Kyber keys");
        }
        
        memcpy(m_kyberPublicKey, kyberPubData.constData(), OQS_KEM_kyber_1024_length_public_key);
        memcpy(m_kyberSecretKey, kyberPrivData.constData(), OQS_KEM_kyber_1024_length_secret_key);
        
        // Allocate and copy Dilithium keys
        m_dilithiumPublicKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_public_key)
        );
        m_dilithiumSecretKey = static_cast<uint8_t*>(
            OQS_MEM_malloc(OQS_SIG_ml_dsa_65_length_secret_key)
        );
        
        if (!m_dilithiumPublicKey || !m_dilithiumSecretKey) {
            throw std::runtime_error("Failed to allocate memory for Dilithium keys");
        }
        
        memcpy(m_dilithiumPublicKey, dilithiumPubData.constData(), OQS_SIG_ml_dsa_65_length_public_key);
        memcpy(m_dilithiumSecretKey, dilithiumPrivData.constData(), OQS_SIG_ml_dsa_65_length_secret_key);
        
        // Reconstruct combined public key hex
        QByteArray combinedPubKey;
        combinedPubKey.append(kyberPubData);
        combinedPubKey.append(dilithiumPubData);
        m_publicKeyHex = combinedPubKey.toHex().toUpper();
        
        qDebug() << "KeyManager: Key pair imported successfully";
        emit keysGenerated();
        return true;
        
    } catch (const std::exception &e) {
        cleanupKeys();
        qWarning() << "KeyManager: Failed to import key pair:" << e.what();
        emit keyOperationFailed(QString("Key import failed: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Exports the Kyber-1024 private key as hex string
 * @param type Key type (KEM or Signature)
 * @return QString Hex-encoded private key, empty if key doesn't exist
 */
QString KeyManager::exportPrivateKey(KeyType type) const
{
    if (type == KeyType::KEM && m_kyberSecretKey) {
        QByteArray keyData(
            reinterpret_cast<char*>(m_kyberSecretKey),
            OQS_KEM_kyber_1024_length_secret_key
        );
        return keyData.toHex().toUpper();
    } else if (type == KeyType::Signature && m_dilithiumSecretKey) {
        QByteArray keyData(
            reinterpret_cast<char*>(m_dilithiumSecretKey),
            OQS_SIG_ml_dsa_65_length_secret_key
        );
        return keyData.toHex().toUpper();
    }
    
    return QString();
}

/**
 * @brief Exports the public key as hex string
 * @param type Key type (KEM or Signature)
 * @return QString Hex-encoded public key, empty if key doesn't exist
 */
QString KeyManager::exportPublicKey(KeyType type) const
{
    if (type == KeyType::KEM && m_kyberPublicKey) {
        QByteArray keyData(
            reinterpret_cast<char*>(m_kyberPublicKey),
            OQS_KEM_kyber_1024_length_public_key
        );
        return keyData.toHex().toUpper();
    } else if (type == KeyType::Signature && m_dilithiumPublicKey) {
        QByteArray keyData(
            reinterpret_cast<char*>(m_dilithiumPublicKey),
            OQS_SIG_ml_dsa_65_length_public_key
        );
        return keyData.toHex().toUpper();
    }
    
    return QString();
}

/**
 * @brief Exports the combined public key (Kyber + Dilithium) as hex
 * @return QString Hex-encoded combined public key
 */
QString KeyManager::exportCombinedPublicKey() const
{
    return m_publicKeyHex;
}

/**
 * @brief Generates a deterministic symmetric key from PQ keys
 *
 * Creates a consistent key for symmetric encryption/decryption
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
 * 3. Hash with SHA-256 to produce requested key length
 *
 * @param keyLength Desired key length in bytes (default 32)
 * @return QByteArray Deterministic symmetric key of requested length
 */
QByteArray KeyManager::generateDeterministicKey(int keyLength) const
{
    if (!hasKeys()) {
        qWarning() << "KeyManager: Cannot generate deterministic key without keys";
        return QByteArray();
    }
    
    // Create key material from PQ keys
    QByteArray keyMaterial;
    
    // Combine Kyber and Dilithium keys for maximum entropy
    if (m_kyberSecretKey) {
        keyMaterial.append(
            reinterpret_cast<char*>(m_kyberSecretKey),
            OQS_KEM_kyber_1024_length_secret_key
        );
    }
    if (m_dilithiumSecretKey) {
        keyMaterial.append(
            reinterpret_cast<char*>(m_dilithiumSecretKey),
            OQS_SIG_ml_dsa_65_length_secret_key
        );
    }
    
    // Add a fixed salt for key derivation to prevent attacks
    // This separates the key derivation domain from other uses
    keyMaterial.append("cybou_pq_key_derivation_salt_2024");
    
    // Hash to get the requested key length
    QByteArray hash = QCryptographicHash::hash(keyMaterial, QCryptographicHash::Sha256);
    
    // If more bytes are needed, hash again (simple key expansion)
    while (hash.size() < keyLength) {
        hash.append(QCryptographicHash::hash(hash, QCryptographicHash::Sha256));
    }
    
    return hash.left(keyLength);
}

/**
 * @brief Checks if both key pairs are available
 * @return bool True if Kyber and Dilithium keys exist
 */
bool KeyManager::hasKeys() const
{
    return m_kyberPublicKey && m_kyberSecretKey && 
           m_dilithiumPublicKey && m_dilithiumSecretKey;
}

/**
 * @brief Gets pointer to Kyber public key (for internal use)
 * @return const uint8_t* Pointer to key data, nullptr if not available
 */
const uint8_t* KeyManager::getKyberPublicKey() const
{
    return m_kyberPublicKey;
}

/**
 * @brief Gets pointer to Kyber secret key (for internal use)
 * @return const uint8_t* Pointer to key data, nullptr if not available
 */
const uint8_t* KeyManager::getKyberSecretKey() const
{
    return m_kyberSecretKey;
}

/**
 * @brief Gets pointer to Dilithium public key (for internal use)
 * @return const uint8_t* Pointer to key data, nullptr if not available
 */
const uint8_t* KeyManager::getDilithiumPublicKey() const
{
    return m_dilithiumPublicKey;
}

/**
 * @brief Gets pointer to Dilithium secret key (for internal use)
 * @return const uint8_t* Pointer to key data, nullptr if not available
 */
const uint8_t* KeyManager::getDilithiumSecretKey() const
{
    return m_dilithiumSecretKey;
}

/**
 * @brief Securely wipes all key material from memory
 * 
 * Uses OQS_MEM_secure_free to ensure keys are properly zeroed
 * before deallocation, preventing memory recovery attacks.
 */
void KeyManager::cleanupKeys()
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
