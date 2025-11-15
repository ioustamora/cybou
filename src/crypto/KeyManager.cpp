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
        
        emit keysChanged();
        return true;
        
    } catch (const std::exception &e) {
        cleanupKeys();
        qWarning() << "KeyManager: Failed to generate key pairs:" << e.what();
        return false;
    }
}

/**
 * @brief Imports a key pair from hex-encoded strings
 * 
 * Loads previously exported keys back into the KeyManager. The keys must
 * be in the combined format (Kyber + Dilithium).
 *
 * @param privateKeyHex Hex-encoded combined private key
 * @param publicKeyHex Hex-encoded combined public key
 * @return bool True if import succeeded, false if validation failed
 */
bool KeyManager::importKeyPair(const QString &privateKeyHex, const QString &publicKeyHex)
{
    cleanupKeys();
    
    try {
        QByteArray privateKeyData = QByteArray::fromHex(privateKeyHex.toUtf8());
        QByteArray publicKeyData = QByteArray::fromHex(publicKeyHex.toUtf8());
        
        // Validate combined key lengths
        if (privateKeyData.size() != OQS_KEM_kyber_1024_length_secret_key + OQS_SIG_ml_dsa_65_length_secret_key) {
            throw std::runtime_error("Invalid private key length");
        }
        if (publicKeyData.size() != OQS_KEM_kyber_1024_length_public_key + OQS_SIG_ml_dsa_65_length_public_key) {
            throw std::runtime_error("Invalid public key length");
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
        
        memcpy(m_kyberPublicKey, publicKeyData.constData(), OQS_KEM_kyber_1024_length_public_key);
        memcpy(m_kyberSecretKey, privateKeyData.constData(), OQS_KEM_kyber_1024_length_secret_key);
        
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
        
        memcpy(m_dilithiumPublicKey, publicKeyData.constData() + OQS_KEM_kyber_1024_length_public_key, OQS_SIG_ml_dsa_65_length_public_key);
        memcpy(m_dilithiumSecretKey, privateKeyData.constData() + OQS_KEM_kyber_1024_length_secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
        
        m_publicKeyHex = publicKeyHex.toUpper();
        
        qDebug() << "KeyManager: Key pair imported successfully";
        emit keysChanged();
        return true;
        
    } catch (const std::exception &e) {
        cleanupKeys();
        qWarning() << "KeyManager: Failed to import key pair:" << e.what();
        return false;
    }
}

/**
 * @brief Exports the combined private key as hex string
 * @return QString Hex-encoded private key (Kyber + Dilithium), empty if key doesn't exist
 */
QString KeyManager::exportPrivateKey() const
{
    if (!m_kyberSecretKey || !m_dilithiumSecretKey) {
        return QString();
    }
    
    QByteArray combinedPrivateKey;
    combinedPrivateKey.append(
        reinterpret_cast<char*>(m_kyberSecretKey),
        OQS_KEM_kyber_1024_length_secret_key
    );
    combinedPrivateKey.append(
        reinterpret_cast<char*>(m_dilithiumSecretKey),
        OQS_SIG_ml_dsa_65_length_secret_key
    );
    
    return combinedPrivateKey.toHex().toUpper();
}

/**
 * @brief Exports the combined public key as hex string
 * @return QString Hex-encoded public key (Kyber + Dilithium)
 */
QString KeyManager::exportPublicKey() const
{
    return m_publicKeyHex;
}

/**
 * @brief Gets the combined public key in hex format
 * @return QString Public key string for display/export
 */
QString KeyManager::publicKey() const
{
    return m_publicKeyHex;
}

/**
 * @brief Gets the algorithm identification string
 * @return QString Description of algorithms in use
 */
QString KeyManager::keyAlgorithm() const
{
    return "Kyber-1024 + ML-DSA-65";
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
 * @return QByteArray Deterministic symmetric key (32 bytes)
 */
QByteArray KeyManager::generateDeterministicKey()
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
    
    // Hash to get a 32-byte (256-bit) key suitable for symmetric encryption
    QByteArray hash = QCryptographicHash::hash(keyMaterial, QCryptographicHash::Sha256);
    return hash;
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
