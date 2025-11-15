/**
 * @file KeyManager.h
 * @brief Post-quantum key management and generation
 *
 * This module handles all key-related operations including:
 * - Key pair generation (Kyber-1024 + ML-DSA-65)
 * - Key import/export functionality
 * - Secure key storage and cleanup
 * - Key derivation for symmetric operations
 *
 * Separates key management from cryptographic operations for better
 * modularity and maintainability.
 */

#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>

extern "C" {
#include <oqs/oqs.h>
}

/**
 * @class KeyManager
 * @brief Manages post-quantum cryptographic keys
 *
 * This class is responsible for:
 * - Generating new Kyber-1024 and ML-DSA-65 key pairs
 * - Importing/exporting keys in hexadecimal format
 * - Securely storing keys in memory
 * - Deriving deterministic symmetric keys for encryption
 * - Cleaning up sensitive key material
 *
 * All key operations use OQS secure memory allocation and deallocation
 * to prevent key material from being exposed in memory dumps.
 */
class KeyManager : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool hasKeys READ hasKeys NOTIFY keysChanged)
    Q_PROPERTY(QString publicKey READ publicKey NOTIFY keysChanged)
    Q_PROPERTY(QString keyAlgorithm READ keyAlgorithm CONSTANT)

public:
    /**
     * @brief Constructs a KeyManager instance
     * @param parent Parent QObject for memory management
     */
    explicit KeyManager(QObject *parent = nullptr);

    /**
     * @brief Destroys KeyManager and securely cleans up keys
     */
    ~KeyManager();

    /**
     * @brief Generates a new Kyber-1024 + ML-DSA-65 key pair
     *
     * Creates quantum-resistant key pairs using cryptographically secure
     * random number generation. Keys are stored internally using OQS
     * secure memory allocation.
     *
     * @return bool True if key generation succeeded, false otherwise
     */
    bool generateKeyPair();

    /**
     * @brief Imports key pairs from hexadecimal strings
     *
     * Loads previously exported keys into the key manager.
     * Keys must be in the combined format (Kyber + Dilithium).
     * Validates key lengths before import.
     *
     * @param privateKeyHex Hexadecimal string of combined private key
     * @param publicKeyHex Hexadecimal string of combined public key
     * @return bool True if import succeeded and keys are valid
     */
    bool importKeyPair(const QString &privateKeyHex, const QString &publicKeyHex);

    /**
     * @brief Exports the private key as a hexadecimal string
     * @return QString Combined private key (Kyber + Dilithium) in hex format
     * @warning This contains sensitive material and should be handled securely
     */
    QString exportPrivateKey() const;

    /**
     * @brief Exports the public key as a hexadecimal string
     * @return QString Combined public key (Kyber + Dilithium) in hex format
     */
    QString exportPublicKey() const;

    /**
     * @brief Checks if keys have been generated or imported
     * @return bool True if valid keys are loaded
     */
    bool hasKeys() const;

    /**
     * @brief Gets the combined public key in hex format
     * @return QString Public key string for display/export
     */
    QString publicKey() const;

    /**
     * @brief Gets the algorithm identification string
     * @return QString Description of algorithms in use
     */
    QString keyAlgorithm() const;

    /**
     * @brief Derives a deterministic symmetric key from PQ keys
     *
     * Creates a consistent 256-bit key using SHA-256 hash of the
     * Kyber public key. This ensures encryption/decryption operations
     * produce consistent results.
     *
     * @return QByteArray 32-byte symmetric key for AES encryption
     */
    QByteArray generateDeterministicKey();

    // Accessor methods for key material (used by crypto operations)
    uint8_t* kyberPublicKey() { return m_kyberPublicKey; }
    uint8_t* kyberSecretKey() { return m_kyberSecretKey; }
    uint8_t* dilithiumPublicKey() { return m_dilithiumPublicKey; }
    uint8_t* dilithiumSecretKey() { return m_dilithiumSecretKey; }

    const uint8_t* kyberPublicKey() const { return m_kyberPublicKey; }
    const uint8_t* kyberSecretKey() const { return m_kyberSecretKey; }
    const uint8_t* dilithiumPublicKey() const { return m_dilithiumPublicKey; }
    const uint8_t* dilithiumSecretKey() const { return m_dilithiumSecretKey; }

signals:
    /**
     * @brief Emitted when keys are generated, imported, or cleared
     */
    void keysChanged();

private:
    /**
     * @brief Initializes OQS library and checks algorithm availability
     * @return bool True if required algorithms are enabled
     */
    bool initializeOQS();

    /**
     * @brief Securely cleans up and frees all key material
     *
     * Uses OQS_MEM_secure_free to overwrite key data before deallocation.
     * Prevents sensitive keys from remaining in memory.
     */
    void cleanupKeys();

    // Key storage (allocated using OQS secure memory functions)
    uint8_t *m_kyberPublicKey = nullptr;     ///< Kyber-1024 public key (1568 bytes)
    uint8_t *m_kyberSecretKey = nullptr;     ///< Kyber-1024 secret key (3168 bytes)
    uint8_t *m_dilithiumPublicKey = nullptr; ///< ML-DSA-65 public key (2592 bytes)
    uint8_t *m_dilithiumSecretKey = nullptr; ///< ML-DSA-65 secret key (4864 bytes)

    QString m_publicKeyHex; ///< Cached combined public key in hex format
};
