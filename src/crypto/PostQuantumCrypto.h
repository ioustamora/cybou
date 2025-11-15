/**
 * @file PostQuantumCrypto.h
 * @brief Post-quantum cryptographic operations facade
 *
 * This class provides a unified interface to quantum-resistant cryptographic
 * functionality by delegating to specialized modules:
 * - KeyManager: Key generation, import/export, deterministic derivation
 * - EncryptionEngine: Text and file encryption/decryption
 * - SignatureEngine: Digital signatures and key encapsulation
 *
 * This facade pattern maintains backward compatibility while providing
 * better code organization and separation of concerns.
 */

#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QVariantMap>

// Forward declarations for specialized modules
class KeyManager;
class EncryptionEngine;
class SignatureEngine;

/**
 * @class PostQuantumCrypto
 * @brief Provides post-quantum cryptographic operations
 *
 * This class implements quantum-resistant cryptography using NIST-standard algorithms:
 * - Kyber-1024 (Level 5 security): For key encapsulation and shared secret derivation
 * - ML-DSA-65 (Level 5 security): For digital signatures and authentication
 *
 * Key features:
 * - Hybrid encryption combining PQ algorithms with symmetric cryptography
 * - Deterministic key derivation from PQ keys for consistent encrypt/decrypt
 * - File and text encryption/decryption with proper binary handling
 * - Digital signature creation and verification
 * - Secure key management with automatic cleanup
 *
 * All cryptographic operations are performed using the liboqs library,
 * ensuring compliance with NIST post-quantum standards.
 */
class PostQuantumCrypto : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool hasKeys READ hasKeys NOTIFY keysChanged)
    Q_PROPERTY(QString publicKey READ publicKey NOTIFY keysChanged)
    Q_PROPERTY(QString keyAlgorithm READ keyAlgorithm CONSTANT)

public:
    /**
     * @brief Constructs a PostQuantumCrypto instance
     * @param parent Parent QObject for memory management
     */
    explicit PostQuantumCrypto(QObject *parent = nullptr);

    /**
     * @brief Destroys the PostQuantumCrypto instance and securely cleans up keys
     */
    ~PostQuantumCrypto();

    /**
     * @brief Generates a new Kyber-1024 + ML-DSA-65 key pair
     *
     * Creates quantum-resistant key pairs using cryptographically secure
     * random number generation. The keys are stored internally and used
     * for all subsequent cryptographic operations.
     *
     * @return bool True if key generation succeeded
     */
    Q_INVOKABLE bool generateKeyPair();

    /**
     * @brief Imports key pairs from hexadecimal strings
     *
     * Loads previously exported keys into the crypto engine.
     * Keys must be in the combined format (Kyber + Dilithium).
     *
     * @param privateKeyHex Hexadecimal string of the combined private key
     * @param publicKeyHex Hexadecimal string of the combined public key
     * @return bool True if import succeeded
     */
    Q_INVOKABLE bool importKeyPair(const QString &privateKeyHex, const QString &publicKeyHex);

    /**
     * @brief Exports the private key as a hexadecimal string
     * @return QString Combined private key (Kyber + Dilithium) in hex format
     */
    Q_INVOKABLE QString exportPrivateKey() const;

    /**
     * @brief Exports the public key as a hexadecimal string
     * @return QString Combined public key (Kyber + Dilithium) in hex format
     */
    Q_INVOKABLE QString exportPublicKey() const;

    /**
     * @brief Signs a message using ML-DSA-65
     *
     * Creates a quantum-resistant digital signature for the given message.
     * The signature can be verified by anyone with the corresponding public key.
     *
     * @param message The message to sign
     * @return QString Signature in hexadecimal format, or empty string on failure
     */
    Q_INVOKABLE QString signMessage(const QString &message);

    /**
     * @brief Verifies a signature using ML-DSA-65
     *
     * Verifies that a signature was created by the owner of the provided public key.
     *
     * @param message The original message
     * @param signature Hexadecimal signature to verify
     * @param publicKeyHex Public key in hexadecimal format
     * @return bool True if signature is valid
     */
    Q_INVOKABLE bool verifySignature(const QString &message, const QString &signature, const QString &publicKeyHex);

    /**
     * @brief Performs Kyber key encapsulation with a recipient's public key
     *
     * Generates a shared secret that can only be decapsulated by the holder
     * of the corresponding private key. Returns both the ciphertext and
     * the shared secret for the sender.
     *
     * @param recipientPublicKeyHex Recipient's combined public key in hex
     * @return QVariantMap Contains "ciphertext" and "sharedSecret" fields
     */
    Q_INVOKABLE QVariantMap encapsulateKey(const QString &recipientPublicKeyHex);

    /**
     * @brief Decapsulates a Kyber ciphertext to obtain the shared secret
     *
     * Uses the private Kyber key to recover the shared secret from an
     * encapsulated key. This completes the key exchange process.
     *
     * @param encapsulatedKey Map containing the ciphertext from encapsulateKey
     * @return QByteArray The shared secret, or empty array on failure
     */
    Q_INVOKABLE QByteArray decapsulateKey(const QVariantMap &encapsulatedKey);

    /**
     * @brief Encrypts text using deterministic symmetric encryption
     *
     * Encrypts plaintext using a symmetric key derived deterministically
     * from the PQ keys. This ensures encrypt/decrypt round-trip consistency.
     *
     * @param plaintext The text to encrypt
     * @return QString Base64-encoded ciphertext, or empty string on failure
     */
    Q_INVOKABLE QString encryptText(const QString &plaintext);

    /**
     * @brief Decrypts text using deterministic symmetric decryption
     *
     * Decrypts ciphertext using the same deterministic key derivation
     * used for encryption.
     *
     * @param ciphertext Base64-encoded ciphertext to decrypt
     * @return QString Decrypted plaintext, or empty string on failure
     */
    Q_INVOKABLE QString decryptText(const QString &ciphertext);

    /**
     * @brief Saves encrypted text to a file
     *
     * Writes encrypted text content to a file for persistent storage.
     *
     * @param content The encrypted text to save
     * @param filePath Path where to save the file
     * @return bool True if save succeeded
     */
    Q_INVOKABLE bool saveEncryptedTextToFile(const QString &content, const QString &filePath);

    /**
     * @brief Loads encrypted text from a file
     *
     * Reads encrypted text content from a file.
     *
     * @param filePath Path to the file to read
     * @return QString The encrypted text content, or empty string on failure
     */
    Q_INVOKABLE QString loadEncryptedTextFromFile(const QString &filePath);

    /**
     * @brief Encrypts a file using binary encryption
     *
     * Reads a file as binary data, encrypts it, and writes the result
     * to a new file with .cybou extension.
     *
     * @param inputFilePath Path to the file to encrypt
     * @param outputFilePath Path for the encrypted output file
     * @return bool True if encryption succeeded
     */
    Q_INVOKABLE bool encryptFile(const QString &inputFilePath, const QString &outputFilePath);

    /**
     * @brief Decrypts a file using binary decryption
     *
     * Reads an encrypted .cybou file, decrypts it, and writes the result
     * to the specified output path.
     *
     * @param inputFilePath Path to the encrypted file
     * @param outputFilePath Path for the decrypted output file
     * @return bool True if decryption succeeded
     */
    Q_INVOKABLE bool decryptFile(const QString &inputFilePath, const QString &outputFilePath);

    /**
     * @brief Encrypts binary data directly
     *
     * Low-level binary encryption using deterministic key derivation.
     * Used internally by file encryption functions.
     *
     * @param plaintext Binary data to encrypt
     * @return QByteArray Encrypted binary data with IV prepended
     */
    Q_INVOKABLE QByteArray encryptBinary(const QByteArray &plaintext);

    /**
     * @brief Decrypts binary data directly
     *
     * Low-level binary decryption using deterministic key derivation.
     * Used internally by file decryption functions.
     *
     * @param ciphertext Binary data to decrypt (with IV prepended)
     * @return QByteArray Decrypted binary data
     */
    Q_INVOKABLE QByteArray decryptBinary(const QByteArray &ciphertext);

    /**
     * @brief Generates a shared secret using Kyber key encapsulation
     *
     * Performs unilateral key exchange by encapsulating a key with
     * another party's public key.
     *
     * @param otherPublicKeyHex The other party's combined public key in hex
     * @return QString Shared secret in hexadecimal format
     */
    Q_INVOKABLE QString generateSharedSecret(const QString &otherPublicKeyHex);

    /**
     * @brief Checks if cryptographic keys are available
     * @return bool True if both Kyber and Dilithium keys are loaded
     */
    bool hasKeys() const { return m_kyberPublicKey != nullptr && m_dilithiumPublicKey != nullptr; }

    /**
     * @brief Gets the combined public key
     * @return QString Combined Kyber + Dilithium public key in hex format
     */
    QString publicKey() const { return m_publicKeyHex; }

    /**
     * @brief Gets the algorithm description
     * @return QString Description of the cryptographic algorithms used
     */
    QString keyAlgorithm() const { return QStringLiteral("Kyber-1024/Dilithium"); }

signals:
    /**
     * @brief Emitted when keys are generated, imported, or cleared
     */
    void keysChanged();

    /**
     * @brief Emitted after cryptographic operations to report results
     * @param operation Name of the operation performed
     * @param success Whether the operation succeeded
     * @param result Additional result information or error message
     */
    void operationCompleted(const QString &operation, bool success, const QString &result);

    /**
     * @brief Emitted during file operations to report progress
     * @param operation Name of the operation (encryptFile/decryptFile)
     * @param progress Progress percentage (0-100)
     * @param status Current status message
     */
    void operationProgress(const QString &operation, int progress, const QString &status);

private:
    // Forward declarations for specialized modules
    class KeyManager *m_keyManager;           ///< Handles key generation and management
    class EncryptionEngine *m_encryptionEngine; ///< Handles encryption/decryption
    class SignatureEngine *m_signatureEngine;   ///< Handles signatures and key encapsulation
};