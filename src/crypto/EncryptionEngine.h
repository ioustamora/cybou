/**
 * @file EncryptionEngine.h
 * @brief Text and file encryption/decryption operations
 *
 * This module provides encryption and decryption functionality using
 * post-quantum derived symmetric keys. Handles:
 * - Text encryption/decryption with Base64 encoding
 * - File encryption/decryption with progress reporting
 * - Binary-safe data handling
 * - Chunked processing for large files
 *
 * Separates encryption logic from key management for cleaner architecture.
 */

#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>

// Forward declaration
class KeyManager;

/**
 * @class EncryptionEngine
 * @brief Handles encryption and decryption operations
 *
 * This class is responsible for:
 * - Encrypting/decrypting text with Base64 encoding
 * - Encrypting/decrypting files with progress reporting
 * - Chunked file processing for memory efficiency
 * - Binary-safe data handling
 *
 * Uses symmetric encryption with keys derived from post-quantum
 * key pairs managed by KeyManager.
 */
class EncryptionEngine : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an EncryptionEngine with a key manager
     * @param keyManager Pointer to KeyManager for key derivation
     * @param parent Parent QObject for memory management
     */
    explicit EncryptionEngine(KeyManager *keyManager, QObject *parent = nullptr);

    /**
     * @brief Encrypts plaintext using deterministic symmetric encryption
     *
     * Encrypts text using a symmetric key derived from PQ keys.
     * Output is Base64 encoded for safe text transmission.
     *
     * @param plaintext The text to encrypt
     * @return QString Base64-encoded ciphertext, or empty on failure
     */
    QString encryptText(const QString &plaintext);

    /**
     * @brief Decrypts Base64-encoded ciphertext
     *
     * Decrypts text that was previously encrypted with encryptText().
     * Uses the same deterministic key derivation for consistency.
     *
     * @param ciphertext Base64-encoded encrypted text
     * @return QString Decrypted plaintext, or empty on failure
     */
    QString decryptText(const QString &ciphertext);

    /**
     * @brief Encrypts a file with progress reporting
     *
     * Encrypts file contents and saves to output path with .cybou extension.
     * Processes files in chunks to handle large files efficiently.
     * Emits progress signals during operation.
     *
     * @param inputFilePath Path to file to encrypt
     * @param outputFilePath Path where encrypted file will be saved
     * @return bool True if encryption succeeded
     */
    bool encryptFile(const QString &inputFilePath, const QString &outputFilePath);

    /**
     * @brief Decrypts a .cybou file with progress reporting
     *
     * Decrypts a file that was encrypted with encryptFile().
     * Processes in chunks and emits progress updates.
     *
     * @param inputFilePath Path to .cybou file to decrypt
     * @param outputFilePath Path where decrypted file will be saved
     * @return bool True if decryption succeeded
     */
    bool decryptFile(const QString &inputFilePath, const QString &outputFilePath);

    /**
     * @brief Encrypts binary data
     *
     * Low-level encryption for QByteArray data.
     * Used internally by file encryption.
     *
     * @param data Binary data to encrypt
     * @return QByteArray Encrypted data
     */
    QByteArray encryptBinary(const QByteArray &data);

    /**
     * @brief Decrypts binary data
     *
     * Low-level decryption for QByteArray data.
     * Used internally by file decryption.
     *
     * @param data Encrypted binary data
     * @return QByteArray Decrypted data
     */
    QByteArray decryptBinary(const QByteArray &data);

    /**
     * @brief Saves text content to a file
     *
     * Utility method for saving encrypted/decrypted text.
     *
     * @param content Text content to save
     * @param filePath Destination file path
     * @return bool True if save succeeded
     */
    bool saveTextToFile(const QString &content, const QString &filePath);

    /**
     * @brief Loads text content from a file
     *
     * Utility method for loading encrypted/decrypted text.
     *
     * @param filePath Source file path
     * @return QString File contents, or empty on failure
     */
    QString loadTextFromFile(const QString &filePath);

signals:
    /**
     * @brief Emitted when an operation completes
     * @param operation Name of operation (encryptFile/decryptFile)
     * @param success Whether operation succeeded
     * @param message Status or error message
     */
    void operationCompleted(const QString &operation, bool success, const QString &message);

    /**
     * @brief Emitted during file operations to report progress
     * @param operation Name of operation (encryptFile/decryptFile)
     * @param progress Percentage complete (0-100)
     * @param status Current status message
     */
    void operationProgress(const QString &operation, int progress, const QString &status);

private:
    /**
     * @brief Performs XOR-based encryption/decryption
     *
     * Simple symmetric cipher using XOR with derived key.
     * Same operation for both encrypt and decrypt (XOR property).
     *
     * @param data Data to encrypt/decrypt
     * @param key Symmetric key for operation
     * @return QByteArray Result of XOR operation
     */
    QByteArray xorEncryptDecrypt(const QByteArray &data, const QByteArray &key);

    KeyManager *m_keyManager; ///< Pointer to key manager for key derivation
};
