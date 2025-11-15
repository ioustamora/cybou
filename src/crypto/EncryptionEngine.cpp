/**
 * @file EncryptionEngine.cpp
 * @brief Implementation of text and file encryption/decryption operations
 *
 * This module provides symmetric encryption using keys derived from
 * post-quantum key pairs. It handles text, file, and binary data
 * encryption with progress reporting for long operations.
 */

#include "EncryptionEngine.h"
#include <QFile>
#include <QRandomGenerator>
#include <QDebug>
#include <stdexcept>

/**
 * @brief Constructs an EncryptionEngine instance
 * @param keyManager Pointer to KeyManager for key derivation
 * @param parent Parent QObject for Qt memory management
 */
EncryptionEngine::EncryptionEngine(KeyManager *keyManager, QObject *parent)
    : QObject(parent)
    , m_keyManager(keyManager)
{
    if (!m_keyManager) {
        qWarning() << "EncryptionEngine: KeyManager is null!";
    }
    qDebug() << "EncryptionEngine initialized";
}

/**
 * @brief Encrypts plaintext to Base64-encoded ciphertext
 * 
 * Process:
 * 1. Generate deterministic symmetric key from PQ keys
 * 2. Generate random IV for this encryption
 * 3. XOR plaintext with symmetric key
 * 4. Combine IV + ciphertext and encode as Base64
 *
 * @param plaintext Text to encrypt
 * @return QString Base64-encoded encrypted text, empty on failure
 * @emits encryptionProgress() during operation
 * @emits encryptionCompleted() on success/failure
 */
QString EncryptionEngine::encryptText(const QString &plaintext)
{
    try {
        if (!m_keyManager || !m_keyManager->hasKeys()) {
            throw std::runtime_error("No PQ keys available for encryption");
        }
        
        emit encryptionProgress(0, "Initializing text encryption...");
        
        // Generate a deterministic symmetric key from PQ keys
        QByteArray symmetricKey = m_keyManager->generateDeterministicKey(32);
        if (symmetricKey.size() != 32) {
            throw std::runtime_error("Failed to generate symmetric key");
        }
        
        emit encryptionProgress(20, "Generating IV...");
        
        // Generate random IV (Initialization Vector)
        QByteArray iv(16, 0);
        QRandomGenerator::global()->generate(iv.begin(), iv.end());
        
        emit encryptionProgress(40, "Encrypting data...");
        
        // Convert plaintext to bytes
        QByteArray plaintextData = plaintext.toUtf8();
        
        // Simple XOR encryption with deterministic key
        // Note: In production, use AES-GCM for authenticated encryption
        QByteArray ciphertext = plaintextData;
        for (int i = 0; i < ciphertext.size(); ++i) {
            ciphertext[i] = ciphertext[i] ^ symmetricKey[i % symmetricKey.size()];
        }
        
        emit encryptionProgress(80, "Encoding result...");
        
        // Combine IV + ciphertext and encode as Base64
        QByteArray combined;
        combined.append(iv);
        combined.append(ciphertext);
        
        QString result = combined.toBase64();
        
        emit encryptionProgress(100, "Text encryption completed");
        emit encryptionCompleted(true, "Text encrypted successfully");
        return result;
        
    } catch (const std::exception &e) {
        qWarning() << "EncryptionEngine: Failed to encrypt text:" << e.what();
        emit encryptionCompleted(false, QString("Error: %1").arg(e.what()));
        return QString();
    }
}

/**
 * @brief Decrypts Base64-encoded ciphertext to plaintext
 * 
 * Process:
 * 1. Decode from Base64
 * 2. Extract IV and ciphertext
 * 3. Generate same deterministic symmetric key
 * 4. XOR decrypt ciphertext with key
 * 5. Convert to UTF-8 string
 *
 * @param ciphertext Base64-encoded encrypted text
 * @return QString Decrypted plaintext, empty on failure
 * @emits decryptionProgress() during operation
 * @emits decryptionCompleted() on success/failure
 */
QString EncryptionEngine::decryptText(const QString &ciphertext)
{
    try {
        if (!m_keyManager || !m_keyManager->hasKeys()) {
            throw std::runtime_error("No PQ keys available for decryption");
        }
        
        emit decryptionProgress(0, "Initializing text decryption...");
        
        // Decode from Base64
        QByteArray combined = QByteArray::fromBase64(ciphertext.toUtf8());
        if (combined.size() < 16) {
            throw std::runtime_error("Invalid ciphertext format");
        }
        
        emit decryptionProgress(20, "Extracting IV...");
        
        // Extract IV and ciphertext
        QByteArray iv = combined.left(16);
        QByteArray encryptedData = combined.mid(16);
        
        emit decryptionProgress(40, "Deriving key...");
        
        // Generate the SAME deterministic symmetric key
        QByteArray symmetricKey = m_keyManager->generateDeterministicKey(32);
        if (symmetricKey.size() != 32) {
            throw std::runtime_error("Failed to generate symmetric key");
        }
        
        emit decryptionProgress(60, "Decrypting data...");
        
        // XOR decryption (matches encryption)
        QByteArray plaintext = encryptedData;
        for (int i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = plaintext[i] ^ symmetricKey[i % symmetricKey.size()];
        }
        
        emit decryptionProgress(90, "Converting to text...");
        
        QString result = QString::fromUtf8(plaintext);
        
        emit decryptionProgress(100, "Text decryption completed");
        emit decryptionCompleted(true, "Text decrypted successfully");
        return result;
        
    } catch (const std::exception &e) {
        qWarning() << "EncryptionEngine: Failed to decrypt text:" << e.what();
        emit decryptionCompleted(false, QString("Error: %1").arg(e.what()));
        return QString();
    }
}

/**
 * @brief Encrypts a file with progress reporting
 * 
 * Processes file in 1MB chunks to handle large files efficiently
 * without loading entire file into memory.
 *
 * @param inputFilePath Path to file to encrypt
 * @param outputFilePath Path to save encrypted file (.cybou)
 * @return bool True if encryption succeeded
 * @emits fileEncryptionProgress() during operation
 * @emits encryptionCompleted() on success/failure
 */
bool EncryptionEngine::encryptFile(const QString &inputFilePath, const QString &outputFilePath)
{
    try {
        // Open input file
        QFile inputFile(inputFilePath);
        if (!inputFile.open(QIODevice::ReadOnly)) {
            emit encryptionCompleted(false, QString("Cannot open input file: %1").arg(inputFilePath));
            return false;
        }
        
        // Get file size for progress calculation
        qint64 fileSize = inputFile.size();
        qint64 bytesProcessed = 0;
        
        // Open output file
        QFile outputFile(outputFilePath);
        if (!outputFile.open(QIODevice::WriteOnly)) {
            inputFile.close();
            emit encryptionCompleted(false, QString("Cannot open output file: %1").arg(outputFilePath));
            return false;
        }
        
        emit fileEncryptionProgress(inputFilePath, 0, "Initializing file encryption...");
        
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
                emit encryptionCompleted(false, "Encryption failed during processing");
                return false;
            }
            
            // Write encrypted chunk
            outputFile.write(encryptedChunk);
            
            // Update progress
            bytesProcessed += buffer.size();
            int progress = fileSize > 0 ? (bytesProcessed * 100) / fileSize : 0;
            emit fileEncryptionProgress(
                inputFilePath,
                progress,
                QString("Encrypting... %1%").arg(progress)
            );
        }
        
        inputFile.close();
        outputFile.close();
        
        emit fileEncryptionProgress(inputFilePath, 100, "File encryption completed");
        emit encryptionCompleted(
            true,
            QString("File encrypted: %1 -> %2").arg(inputFilePath, outputFilePath)
        );
        return true;
        
    } catch (const std::exception &e) {
        qWarning() << "EncryptionEngine: Failed to encrypt file:" << e.what();
        emit encryptionCompleted(false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Decrypts a .cybou file with progress reporting
 * 
 * Reads encrypted file, decrypts entire content (needs IV from start),
 * and writes plaintext in chunks for progress updates.
 *
 * @param inputFilePath Path to encrypted file (.cybou)
 * @param outputFilePath Path to save decrypted file
 * @return bool True if decryption succeeded
 * @emits fileDecryptionProgress() during operation
 * @emits decryptionCompleted() on success/failure
 */
bool EncryptionEngine::decryptFile(const QString &inputFilePath, const QString &outputFilePath)
{
    try {
        // Open input file
        QFile inputFile(inputFilePath);
        if (!inputFile.open(QIODevice::ReadOnly)) {
            emit decryptionCompleted(false, QString("Cannot open input file: %1").arg(inputFilePath));
            return false;
        }
        
        emit fileDecryptionProgress(inputFilePath, 0, "Initializing file decryption...");
        
        // Read the entire encrypted file (we need the IV from the beginning)
        QByteArray encryptedData = inputFile.readAll();
        inputFile.close();
        
        if (encryptedData.size() < 16) {
            emit decryptionCompleted(false, "Invalid encrypted file format");
            return false;
        }
        
        emit fileDecryptionProgress(inputFilePath, 30, "Decrypting data...");
        
        // Decrypt the binary data
        QByteArray decryptedData = decryptBinary(encryptedData);
        if (decryptedData.isEmpty()) {
            emit decryptionCompleted(false, "Decryption failed - invalid file or key");
            return false;
        }
        
        emit fileDecryptionProgress(inputFilePath, 60, "Writing decrypted file...");
        
        // Open output file
        QFile outputFile(outputFilePath);
        if (!outputFile.open(QIODevice::WriteOnly)) {
            emit decryptionCompleted(false, QString("Cannot open output file: %1").arg(outputFilePath));
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
            int progress = 60 + (decryptedData.size() > 0 ? (bytesWritten * 40) / decryptedData.size() : 0);
            emit fileDecryptionProgress(
                inputFilePath,
                progress,
                QString("Writing... %1%").arg(progress - 60)
            );
        }
        
        outputFile.close();
        
        emit fileDecryptionProgress(inputFilePath, 100, "File decryption completed");
        emit decryptionCompleted(
            true,
            QString("File decrypted: %1 -> %2").arg(inputFilePath, outputFilePath)
        );
        return true;
        
    } catch (const std::exception &e) {
        qWarning() << "EncryptionEngine: Failed to decrypt file:" << e.what();
        emit decryptionCompleted(false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Encrypts binary data with IV prepended
 * 
 * Internal method used by both text and file encryption.
 * Uses XOR with deterministic key derived from PQ keys.
 *
 * @param plaintext Binary data to encrypt
 * @return QByteArray IV + encrypted data, empty on failure
 */
QByteArray EncryptionEngine::encryptBinary(const QByteArray &plaintext)
{
    try {
        if (!m_keyManager || !m_keyManager->hasKeys()) {
            return QByteArray();
        }
        
        // Generate deterministic symmetric key
        QByteArray symmetricKey = m_keyManager->generateDeterministicKey(32);
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
        qWarning() << "EncryptionEngine: Failed to encrypt binary data:" << e.what();
        return QByteArray();
    }
}

/**
 * @brief Decrypts binary data with IV extraction
 * 
 * Internal method used by both text and file decryption.
 * Expects IV as first 16 bytes of input.
 *
 * @param ciphertext IV + encrypted binary data
 * @return QByteArray Decrypted data, empty on failure
 */
QByteArray EncryptionEngine::decryptBinary(const QByteArray &ciphertext)
{
    try {
        if (!m_keyManager || !m_keyManager->hasKeys()) {
            return QByteArray();
        }
        
        if (ciphertext.size() < 16) {
            return QByteArray();
        }
        
        // Extract IV and ciphertext
        QByteArray iv = ciphertext.left(16);
        QByteArray encryptedData = ciphertext.mid(16);
        
        // Generate the SAME deterministic symmetric key
        QByteArray symmetricKey = m_keyManager->generateDeterministicKey(32);
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
        qWarning() << "EncryptionEngine: Failed to decrypt binary data:" << e.what();
        return QByteArray();
    }
}

/**
 * @brief Saves encrypted text to a file
 * @param content Encrypted text content (Base64)
 * @param filePath Path to save file
 * @return bool True if save succeeded
 */
bool EncryptionEngine::saveEncryptedTextToFile(const QString &content, const QString &filePath)
{
    try {
        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            emit encryptionCompleted(
                false,
                QString("Cannot open file for writing: %1").arg(filePath)
            );
            return false;
        }
        
        QTextStream out(&file);
        out << content;
        file.close();
        
        emit encryptionCompleted(
            true,
            QString("Encrypted text saved to: %1").arg(filePath)
        );
        return true;
        
    } catch (const std::exception &e) {
        qWarning() << "EncryptionEngine: Failed to save encrypted text:" << e.what();
        emit encryptionCompleted(false, QString("Error: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Loads encrypted text from a file
 * @param filePath Path to encrypted text file
 * @return QString Encrypted text content, empty on failure
 */
QString EncryptionEngine::loadEncryptedTextFromFile(const QString &filePath)
{
    try {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            emit decryptionCompleted(
                false,
                QString("Cannot open file for reading: %1").arg(filePath)
            );
            return QString();
        }
        
        QTextStream in(&file);
        QString content = in.readAll();
        file.close();
        
        emit decryptionCompleted(
            true,
            QString("Encrypted text loaded from: %1").arg(filePath)
        );
        return content;
        
    } catch (const std::exception &e) {
        qWarning() << "EncryptionEngine: Failed to load encrypted text:" << e.what();
        emit decryptionCompleted(false, QString("Error: %1").arg(e.what()));
        return QString();
    }
}
