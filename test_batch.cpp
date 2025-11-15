/**
 * @file test_batch.cpp
 * @brief Test suite for batch processing functionality
 *
 * Tests the multi-threaded batch processing capabilities of the PostQuantumCrypto facade.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QTimer>
#include <QEventLoop>

#include "crypto/PostQuantumCrypto.h"

/**
 * @brief Create test files for batch processing
 */
bool createTestFiles(const QStringList& filePaths, const QString& content) {
    for (const QString& filePath : filePaths) {
        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            qWarning() << "Failed to create test file:" << filePath;
            return false;
        }

        QTextStream out(&file);
        out << content;
        file.close();
    }
    return true;
}

/**
 * @brief Clean up test files
 */
void cleanupTestFiles(const QStringList& filePaths) {
    for (const QString& filePath : filePaths) {
        QFile::remove(filePath);
        // Also remove any encrypted/decrypted versions
        QFile::remove(filePath + "_encrypted");
        QFile::remove(filePath + "_decrypted");
    }
}

/**
 * @brief Test batch encryption functionality
 */
bool testBatchEncryption() {
    qDebug() << "Testing batch encryption...";

    // Create test files
    QStringList inputFiles = {
        "test_batch_file1.txt",
        "test_batch_file2.txt",
        "test_batch_file3.txt"
    };

    QString testContent = "This is test content for batch encryption testing.";
    if (!createTestFiles(inputFiles, testContent)) {
        return false;
    }

    // Initialize PostQuantumCrypto
    PostQuantumCrypto crypto;
    if (!crypto.generateKeyPair()) {
        qWarning() << "Failed to generate key pair for PostQuantumCrypto";
        cleanupTestFiles(inputFiles);
        return false;
    }

    // Add files to batch
    crypto.addFilesToBatch(inputFiles, true); // true for encryption

    // Start batch processing
    QEventLoop loop;
    bool batchCompleted = false;
    bool batchSuccess = false;

    // Connect to batch completion signal
    QObject::connect(&crypto, &PostQuantumCrypto::batchCompleted,
                     [&](int total, int success, int error, qint64 timeMs) {
        qDebug() << "Batch completed:" << total << "total," << success << "success," << error << "errors";
        batchCompleted = true;
        batchSuccess = (error == 0);
        loop.quit();
    });

    // Start processing
    crypto.startBatchProcessing();

    // Wait for completion (with timeout)
    QTimer::singleShot(30000, &loop, &QEventLoop::quit); // 30 second timeout
    loop.exec();

    if (!batchCompleted) {
        qWarning() << "Batch processing timed out";
        cleanupTestFiles(inputFiles);
        return false;
    }

    if (!batchSuccess) {
        qWarning() << "Batch processing failed";
        cleanupTestFiles(inputFiles);
        return false;
    }

    // Verify encrypted files exist
    for (const QString& inputFile : inputFiles) {
        QString encryptedFile = inputFile + "_encrypted";
        if (!QFile::exists(encryptedFile)) {
            qWarning() << "Encrypted file not found:" << encryptedFile;
            cleanupTestFiles(inputFiles);
            return false;
        }
    }

    qDebug() << "Batch encryption test passed!";
    cleanupTestFiles(inputFiles);
    return true;
}

/**
 * @brief Test batch decryption functionality
 */
bool testBatchDecryption() {
    qDebug() << "Testing batch decryption...";

    // Create test files
    QStringList inputFiles = {
        "test_batch_decrypt1.txt",
        "test_batch_decrypt2.txt"
    };

    QString testContent = "This is test content for batch decryption testing.";
    if (!createTestFiles(inputFiles, testContent)) {
        return false;
    }

    // Initialize PostQuantumCrypto
    PostQuantumCrypto crypto;
    if (!crypto.generateKeyPair()) {
        qWarning() << "Failed to generate key pair for PostQuantumCrypto";
        cleanupTestFiles(inputFiles);
        return false;
    }

    // First encrypt the files
    crypto.addFilesToBatch(inputFiles, true); // encrypt
    crypto.startBatchProcessing();

    QEventLoop encryptLoop;
    bool encryptCompleted = false;

    QObject::connect(&crypto, &PostQuantumCrypto::batchCompleted,
                     [&](int total, int success, int error, qint64 timeMs) {
        encryptCompleted = true;
        encryptLoop.quit();
    });

    QTimer::singleShot(30000, &encryptLoop, &QEventLoop::quit);
    encryptLoop.exec();

    if (!encryptCompleted) {
        qWarning() << "Encryption phase timed out";
        cleanupTestFiles(inputFiles);
        return false;
    }

    // Now decrypt the encrypted files
    QStringList encryptedFiles;
    for (const QString& inputFile : inputFiles) {
        encryptedFiles << (inputFile + "_encrypted");
    }

    crypto.addFilesToBatch(encryptedFiles, false); // decrypt
    crypto.startBatchProcessing();

    QEventLoop decryptLoop;
    bool decryptCompleted = false;
    bool decryptSuccess = false;

    QObject::connect(&crypto, &PostQuantumCrypto::batchCompleted,
                     [&](int total, int success, int error, qint64 timeMs) {
        qDebug() << "Decryption batch completed:" << total << "total," << success << "success," << error << "errors";
        decryptCompleted = true;
        decryptSuccess = (error == 0);
        decryptLoop.quit();
    });

    QTimer::singleShot(30000, &decryptLoop, &QEventLoop::quit);
    decryptLoop.exec();

    if (!decryptCompleted || !decryptSuccess) {
        qWarning() << "Batch decryption failed";
        cleanupTestFiles(inputFiles);
        return false;
    }

    // Verify decrypted files exist and content matches
    for (const QString& inputFile : inputFiles) {
        QString decryptedFile = inputFile + "_encrypted_decrypted";
        if (!QFile::exists(decryptedFile)) {
            qWarning() << "Decrypted file not found:" << decryptedFile;
            cleanupTestFiles(inputFiles);
            return false;
        }

        // Check content
        QFile file(decryptedFile);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qWarning() << "Cannot read decrypted file:" << decryptedFile;
            cleanupTestFiles(inputFiles);
            return false;
        }

        QTextStream in(&file);
        QString content = in.readAll();
        file.close();

        if (content != testContent) {
            qWarning() << "Decrypted content doesn't match original for:" << decryptedFile;
            cleanupTestFiles(inputFiles);
            return false;
        }
    }

    qDebug() << "Batch decryption test passed!";
    cleanupTestFiles(inputFiles);
    return true;
}

/**
 * @brief Main test function
 */
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    qDebug() << "Starting batch processing tests...";

    bool allTestsPassed = true;

    // Test batch encryption
    if (!testBatchEncryption()) {
        qWarning() << "Batch encryption test FAILED";
        allTestsPassed = false;
    }

    // Test batch decryption
    if (!testBatchDecryption()) {
        qWarning() << "Batch decryption test FAILED";
        allTestsPassed = false;
    }

    if (allTestsPassed) {
        qDebug() << "SUCCESS: All batch processing tests passed!";
        return 0;
    } else {
        qDebug() << "FAILURE: Some batch processing tests failed!";
        return 1;
    }
}