/**
 * @file PostQuantumCrypto.cpp
 * @brief Facade implementation delegating to specialized cryptographic modules
 *
 * This file provides a unified interface to post-quantum cryptographic operations
 * by delegating to specialized modules:
 * - KeyManager: Key generation, import/export, and deterministic derivation
 * - EncryptionEngine: Text and file encryption/decryption operations
 * - SignatureEngine: Digital signatures and key encapsulation
 *
 * This facade pattern maintains backward compatibility with existing code while
 * providing better separation of concerns and modularity.
 */

#include "PostQuantumCrypto.h"
#include "KeyManager.h"
#include "EncryptionEngine.h"
#include "SignatureEngine.h"

#include <QDebug>

/**
 * @brief Constructs PostQuantumCrypto facade with specialized modules
 *
 * Initializes the three specialized modules and connects their signals
 * to the facade's signals for proper event propagation.
 */
PostQuantumCrypto::PostQuantumCrypto(QObject *parent)
    : QObject(parent)
{
    // Create specialized modules
    m_keyManager = new KeyManager(this);
    m_encryptionEngine = new EncryptionEngine(m_keyManager, this);
    m_signatureEngine = new SignatureEngine(m_keyManager, this);
    m_batchProcessor = new BatchProcessor(m_keyManager, this);
    
    // Connect module signals to facade signals
    connect(m_keyManager, &KeyManager::keysChanged, 
            this, &PostQuantumCrypto::keysChanged);
    
    connect(m_encryptionEngine, &EncryptionEngine::operationCompleted,
            this, &PostQuantumCrypto::operationCompleted);
    connect(m_encryptionEngine, &EncryptionEngine::operationProgress,
            this, &PostQuantumCrypto::operationProgress);
    
    connect(m_signatureEngine, &SignatureEngine::operationCompleted,
            this, &PostQuantumCrypto::operationCompleted);
    
    // Connect batch processor signals
    connect(m_batchProcessor, &BatchProcessor::batchProgressUpdated,
            this, &PostQuantumCrypto::batchProgressUpdated);
    connect(m_batchProcessor, &BatchProcessor::batchCompleted,
            this, &PostQuantumCrypto::batchCompleted);
    connect(m_batchProcessor, &BatchProcessor::fileProgressUpdated,
            this, &PostQuantumCrypto::fileProgressUpdated);
    connect(m_batchProcessor, &BatchProcessor::fileCompleted,
            this, &PostQuantumCrypto::fileCompleted);
    connect(m_batchProcessor, &BatchProcessor::queueChanged,
            this, &PostQuantumCrypto::batchQueueChanged);
    
    qDebug() << "PostQuantumCrypto facade initialized with modular architecture";
}

/**
 * @brief Destroys the facade and its modules
 *
 * Module cleanup is handled automatically through Qt parent-child relationship.
 */
PostQuantumCrypto::~PostQuantumCrypto()
{
    qDebug() << "PostQuantumCrypto facade destroyed";
}

// ============================================================================
// Key Management Operations - Delegated to KeyManager
// ============================================================================

bool PostQuantumCrypto::generateKeyPair()
{
    return m_keyManager->generateKeyPair();
}

bool PostQuantumCrypto::importKeyPair(const QString &privateKeyHex, const QString &publicKeyHex)
{
    return m_keyManager->importKeyPair(privateKeyHex, publicKeyHex);
}

QString PostQuantumCrypto::exportPrivateKey() const
{
    return m_keyManager->exportPrivateKey();
}

QString PostQuantumCrypto::exportPublicKey() const
{
    return m_keyManager->exportPublicKey();
}

bool PostQuantumCrypto::hasKeys() const
{
    return m_keyManager->hasKeys();
}

QString PostQuantumCrypto::publicKey() const
{
    return m_keyManager->publicKey();
}

QString PostQuantumCrypto::keyAlgorithm() const
{
    return m_keyManager->keyAlgorithm();
}

// ============================================================================
// Text Encryption Operations - Delegated to EncryptionEngine
// ============================================================================

QString PostQuantumCrypto::encryptText(const QString &plaintext)
{
    return m_encryptionEngine->encryptText(plaintext);
}

QString PostQuantumCrypto::decryptText(const QString &ciphertext)
{
    return m_encryptionEngine->decryptText(ciphertext);
}

bool PostQuantumCrypto::saveEncryptedTextToFile(const QString &content, const QString &filePath)
{
    return m_encryptionEngine->saveTextToFile(content, filePath);
}

QString PostQuantumCrypto::loadEncryptedTextFromFile(const QString &filePath)
{
    return m_encryptionEngine->loadTextFromFile(filePath);
}

// ============================================================================
// File Encryption Operations - Delegated to EncryptionEngine
// ============================================================================

bool PostQuantumCrypto::encryptFile(const QString &inputFilePath, const QString &outputFilePath)
{
    return m_encryptionEngine->encryptFile(inputFilePath, outputFilePath);
}

bool PostQuantumCrypto::decryptFile(const QString &inputFilePath, const QString &outputFilePath)
{
    return m_encryptionEngine->decryptFile(inputFilePath, outputFilePath);
}

QByteArray PostQuantumCrypto::encryptBinary(const QByteArray &plaintext)
{
    return m_encryptionEngine->encryptBinary(plaintext);
}

QByteArray PostQuantumCrypto::decryptBinary(const QByteArray &ciphertext)
{
    return m_encryptionEngine->decryptBinary(ciphertext);
}

// ============================================================================
// Digital Signature Operations - Delegated to SignatureEngine
// ============================================================================

QString PostQuantumCrypto::signMessage(const QString &message)
{
    return m_signatureEngine->signMessage(message);
}

bool PostQuantumCrypto::verifySignature(const QString &message, const QString &signature, const QString &publicKeyHex)
{
    return m_signatureEngine->verifySignature(message, signature, publicKeyHex);
}

// ============================================================================
// Key Encapsulation Operations - Delegated to SignatureEngine
// ============================================================================

QVariantMap PostQuantumCrypto::encapsulateKey(const QString &recipientPublicKeyHex)
{
    return m_signatureEngine->encapsulateKey(recipientPublicKeyHex);
}

QByteArray PostQuantumCrypto::decapsulateKey(const QVariantMap &encapsulatedKey)
{
    return m_signatureEngine->decapsulateKey(encapsulatedKey);
}

QString PostQuantumCrypto::generateSharedSecret(const QString &otherPublicKeyHex)
{
    return m_signatureEngine->generateSharedSecret(otherPublicKeyHex);
}

// ============================================================================
// Batch Processing Operations - Delegated to BatchProcessor
// ============================================================================

void PostQuantumCrypto::addFilesToBatch(const QStringList &filePaths, bool encrypt)
{
    BatchOperation operation = encrypt ? BatchOperation::Encrypt : BatchOperation::Decrypt;
    m_batchProcessor->addFiles(filePaths, QString(), operation);
}

void PostQuantumCrypto::startBatchProcessing()
{
    m_batchProcessor->startProcessing();
}

void PostQuantumCrypto::pauseBatchProcessing()
{
    m_batchProcessor->pauseProcessing();
}

void PostQuantumCrypto::resumeBatchProcessing()
{
    m_batchProcessor->resumeProcessing();
}

void PostQuantumCrypto::cancelBatchProcessing()
{
    m_batchProcessor->cancelProcessing();
}

void PostQuantumCrypto::clearBatchQueue()
{
    m_batchProcessor->clearQueue();
}

int PostQuantumCrypto::batchQueueSize() const
{
    return m_batchProcessor->queueSize();
}

int PostQuantumCrypto::batchCompletedCount() const
{
    return m_batchProcessor->completedCount();
}

int PostQuantumCrypto::batchSuccessCount() const
{
    return m_batchProcessor->successCount();
}

int PostQuantumCrypto::batchErrorCount() const
{
    return m_batchProcessor->errorCount();
}

double PostQuantumCrypto::batchOverallProgress() const
{
    return m_batchProcessor->overallProgress();
}

QString PostQuantumCrypto::batchStatusMessage() const
{
    return m_batchProcessor->currentStatusMessage();
}

QVariantList PostQuantumCrypto::batchFileList() const
{
    QVariantList result;
    
    // This is a simplified implementation - in a real app you'd want to expose
    // the actual BatchFileItem data through the BatchProcessor
    // For now, return an empty list as the UI will be updated via signals
    
    return result;
}
