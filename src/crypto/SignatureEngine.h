/**
 * @file SignatureEngine.h
 * @brief Digital signature creation and verification
 *
 * This module handles all signature-related operations using ML-DSA-65:
 * - Message signing for authentication
 * - Signature verification
 * - Public key operations
 *
 * Separates signature logic from other cryptographic operations.
 */

#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QVariantMap>

// Forward declaration
class KeyManager;

/**
 * @class SignatureEngine
 * @brief Handles digital signature operations
 *
 * This class is responsible for:
 * - Creating ML-DSA-65 signatures for messages
 * - Verifying signatures against public keys
 * - Kyber key encapsulation for key exchange
 * - Shared secret generation
 *
 * Uses ML-DSA-65 (formerly Dilithium5) for quantum-resistant signatures.
 */
class SignatureEngine : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a SignatureEngine with a key manager
     * @param keyManager Pointer to KeyManager for key access
     * @param parent Parent QObject for memory management
     */
    explicit SignatureEngine(KeyManager *keyManager, QObject *parent = nullptr);

    /**
     * @brief Signs a message using ML-DSA-65
     *
     * Creates a quantum-resistant digital signature for the message.
     * The signature can be verified by anyone with the public key.
     * Uses deterministic signing for consistency.
     *
     * @param message The message to sign (will be UTF-8 encoded)
     * @return QString Signature in hexadecimal format, empty on failure
     */
    QString signMessage(const QString &message);

    /**
     * @brief Verifies a signature using ML-DSA-65
     *
     * Verifies that a signature was created by the owner of the
     * provided public key. Ensures message authenticity and integrity.
     *
     * @param message The original message
     * @param signature Hexadecimal signature to verify
     * @param publicKeyHex Public key in hexadecimal format (combined Kyber+Dilithium)
     * @return bool True if signature is valid and matches message
     */
    bool verifySignature(const QString &message, const QString &signature, const QString &publicKeyHex);

    /**
     * @brief Performs Kyber key encapsulation
     *
     * Generates a shared secret that can only be decapsulated by
     * the holder of the corresponding private key. Returns both
     * ciphertext and shared secret for the sender.
     *
     * @param recipientPublicKeyHex Recipient's combined public key in hex
     * @return QVariantMap Contains "ciphertext" and "sharedSecret" fields
     */
    QVariantMap encapsulateKey(const QString &recipientPublicKeyHex);

    /**
     * @brief Decapsulates a Kyber ciphertext
     *
     * Uses the private Kyber key to recover the shared secret from
     * an encapsulated key. Completes the key exchange process.
     *
     * @param encapsulatedKey Map containing ciphertext from encapsulateKey
     * @return QByteArray The shared secret, or empty array on failure
     */
    QByteArray decapsulateKey(const QVariantMap &encapsulatedKey);

    /**
     * @brief Generates a shared secret with recipient's public key
     *
     * High-level method that performs key encapsulation and returns
     * the shared secret. Used for establishing secure channels.
     *
     * @param recipientPublicKeyHex Recipient's public key in hex format
     * @return QString Shared secret in hex format
     */
    QString generateSharedSecret(const QString &recipientPublicKeyHex);

signals:
    /**
     * @brief Emitted when a signature operation completes
     * @param operation Name of operation (signMessage/verifySignature/encapsulateKey/decapsulateKey/generateSharedSecret)
     * @param success Whether operation succeeded
     * @param message Status or error message
     */
    void operationCompleted(const QString &operation, bool success, const QString &message);

private:
    KeyManager *m_keyManager; ///< Pointer to key manager for key access
};
