/**
 * @file benchmark_crypto.cpp
 * @brief Performance benchmarking for cryptographic operations
 *
 * Measures performance of key generation, encryption/decryption,
 * and digital signatures to identify bottlenecks and track improvements.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryFile>
#include <QTextStream>
#include "src/crypto/KeyManager.h"
#include "src/crypto/EncryptionEngine.h"
#include "src/crypto/SignatureEngine.h"

/**
 * @brief Benchmark key generation performance
 */
void benchmarkKeyGeneration()
{
    qDebug() << "\n=== Key Generation Benchmark ===";

    KeyManager keyManager;
    QElapsedTimer timer;

    const int iterations = 10;
    qint64 totalTime = 0;

    for (int i = 0; i < iterations; ++i) {
        timer.start();
        bool success = keyManager.generateKeyPair();
        qint64 elapsed = timer.elapsed();

        if (success) {
            totalTime += elapsed;
            qDebug() << QString("Iteration %1: %2 ms").arg(i + 1).arg(elapsed);
        } else {
            qDebug() << QString("Iteration %1: FAILED").arg(i + 1);
        }
    }

    double averageTime = static_cast<double>(totalTime) / iterations;
    qDebug() << QString("Average key generation time: %1 ms").arg(averageTime, 0, 'f', 2);
    qDebug() << QString("Keys per second: %1").arg(1000.0 / averageTime, 0, 'f', 2);
}

/**
 * @brief Benchmark text encryption/decryption performance
 */
void benchmarkTextEncryption(KeyManager *keyManager, EncryptionEngine *encryptionEngine)
{
    qDebug() << "\n=== Text Encryption Benchmark ===";

    // Test different message sizes
    QVector<QString> testMessages = {
        "Short message",
        QString(1000, 'A'),      // 1KB message
        QString(10000, 'B'),     // 10KB message
        QString(100000, 'C'),    // 100KB message
        QString(1000000, 'D')    // 1MB message
    };

    for (const QString &message : testMessages) {
        qDebug() << QString("\nTesting message size: %1 characters (%2 KB)")
                    .arg(message.length())
                    .arg(message.length() / 1024.0, 0, 'f', 2);

        QElapsedTimer timer;

        // Benchmark encryption
        timer.start();
        QString encrypted = encryptionEngine->encryptText(message);
        qint64 encryptTime = timer.elapsed();

        if (!encrypted.isEmpty()) {
            qDebug() << QString("Encryption time: %1 ms (%2 MB/s)")
                        .arg(encryptTime)
                        .arg((message.length() / (1024.0 * 1024.0)) / (encryptTime / 1000.0), 0, 'f', 2);

            // Benchmark decryption
            timer.start();
            QString decrypted = encryptionEngine->decryptText(encrypted);
            qint64 decryptTime = timer.elapsed();

            if (decrypted == message) {
                qDebug() << QString("Decryption time: %1 ms (%2 MB/s)")
                            .arg(decryptTime)
                            .arg((message.length() / (1024.0 * 1024.0)) / (decryptTime / 1000.0), 0, 'f', 2);
                qDebug() << QString("Round-trip time: %1 ms").arg(encryptTime + decryptTime);
            } else {
                qDebug() << "❌ Decryption verification failed!";
            }
        } else {
            qDebug() << "❌ Encryption failed!";
        }
    }
}

/**
 * @brief Benchmark file encryption/decryption performance
 */
void benchmarkFileEncryption(KeyManager *keyManager, EncryptionEngine *encryptionEngine)
{
    qDebug() << "\n=== File Encryption Benchmark ===";

    // Test different file sizes
    QVector<qint64> fileSizes = {
        1024,        // 1KB
        1024 * 100,  // 100KB
        1024 * 1000, // 1MB
        1024 * 10000 // 10MB
    };

    for (qint64 size : fileSizes) {
        qDebug() << QString("\nTesting file size: %1 KB").arg(size / 1024);

        // Create temporary test file
        QTemporaryFile testFile;
        testFile.setAutoRemove(false);
        if (!testFile.open()) {
            qDebug() << "❌ Failed to create test file";
            continue;
        }

        // Fill file with test data
        QByteArray testData(size, 'X');
        testFile.write(testData);
        testFile.close();

        QString inputPath = testFile.fileName();
        QString outputPath = inputPath + ".cybou";

        QElapsedTimer timer;

        // Benchmark encryption
        timer.start();
        bool encryptSuccess = encryptionEngine->encryptFile(inputPath, outputPath);
        qint64 encryptTime = timer.elapsed();

        if (encryptSuccess) {
            qDebug() << QString("Encryption time: %1 ms (%2 MB/s)")
                        .arg(encryptTime)
                        .arg((size / (1024.0 * 1024.0)) / (encryptTime / 1000.0), 0, 'f', 2);

            // Benchmark decryption
            QString decryptOutputPath = inputPath + "_decrypted";
            timer.start();
            bool decryptSuccess = encryptionEngine->decryptFile(outputPath, decryptOutputPath);
            qint64 decryptTime = timer.elapsed();

            if (decryptSuccess) {
                qDebug() << QString("Decryption time: %1 ms (%2 MB/s)")
                            .arg(decryptTime)
                            .arg((size / (1024.0 * 1024.0)) / (decryptTime / 1000.0), 0, 'f', 2);
                qDebug() << QString("Round-trip time: %1 ms").arg(encryptTime + decryptTime);

                // Verify file integrity
                QFile originalFile(inputPath);
                QFile decryptedFile(decryptOutputPath);

                if (originalFile.open(QIODevice::ReadOnly) && decryptedFile.open(QIODevice::ReadOnly)) {
                    QByteArray originalData = originalFile.readAll();
                    QByteArray decryptedData = decryptedFile.readAll();

                    if (originalData == decryptedData) {
                        qDebug() << "✅ File integrity verified";
                    } else {
                        qDebug() << "❌ File integrity check failed!";
                    }

                    originalFile.close();
                    decryptedFile.close();
                }
            } else {
                qDebug() << "❌ Decryption failed!";
            }

            // Clean up
            QFile::remove(outputPath);
            QFile::remove(decryptOutputPath);
        } else {
            qDebug() << "❌ Encryption failed!";
        }

        // Clean up test file
        QFile::remove(inputPath);
    }
}

/**
 * @brief Benchmark digital signature performance
 */
void benchmarkSignatures(KeyManager *keyManager, SignatureEngine *signatureEngine)
{
    qDebug() << "\n=== Digital Signature Benchmark ===";

    // Test different message sizes
    QVector<QString> testMessages = {
        "Short message",
        QString(1000, 'A'),      // 1KB message
        QString(10000, 'B'),     // 10KB message
        QString(100000, 'C')     // 100KB message
    };

    QString publicKey = keyManager->publicKey();

    for (const QString &message : testMessages) {
        qDebug() << QString("\nTesting message size: %1 characters (%2 KB)")
                    .arg(message.length())
                    .arg(message.length() / 1024.0, 0, 'f', 2);

        QElapsedTimer timer;

        // Benchmark signing
        timer.start();
        QString signature = signatureEngine->signMessage(message);
        qint64 signTime = timer.elapsed();

        if (!signature.isEmpty()) {
            qDebug() << QString("Signing time: %1 ms").arg(signTime);

            // Benchmark verification
            timer.start();
            bool verified = signatureEngine->verifySignature(message, signature, publicKey);
            qint64 verifyTime = timer.elapsed();

            if (verified) {
                qDebug() << QString("Verification time: %1 ms").arg(verifyTime);
                qDebug() << QString("Total signature time: %1 ms").arg(signTime + verifyTime);
            } else {
                qDebug() << "❌ Signature verification failed!";
            }
        } else {
            qDebug() << "❌ Signing failed!";
        }
    }
}

/**
 * @brief Benchmark key encapsulation performance
 */
void benchmarkKeyEncapsulation(KeyManager *keyManager, SignatureEngine *signatureEngine)
{
    qDebug() << "\n=== Key Encapsulation Benchmark ===";

    // Create recipient keys
    KeyManager recipientKeyManager;
    if (!recipientKeyManager.generateKeyPair()) {
        qDebug() << "❌ Failed to generate recipient keys";
        return;
    }

    QString recipientPublicKey = recipientKeyManager.publicKey();

    const int iterations = 100;
    qint64 totalEncapTime = 0;
    qint64 totalDecapTime = 0;

    for (int i = 0; i < iterations; ++i) {
        QElapsedTimer timer;

        // Benchmark encapsulation
        timer.start();
        QVariantMap encapResult = signatureEngine->encapsulateKey(recipientPublicKey);
        qint64 encapTime = timer.elapsed();

        if (encapResult.contains("ciphertext")) {
            totalEncapTime += encapTime;

            // Benchmark decapsulation
            SignatureEngine recipientEngine(&recipientKeyManager);
            timer.start();
            QByteArray sharedSecret = recipientEngine.decapsulateKey(encapResult);
            qint64 decapTime = timer.elapsed();

            if (!sharedSecret.isEmpty()) {
                totalDecapTime += decapTime;
            }
        }
    }

    double avgEncapTime = static_cast<double>(totalEncapTime) / iterations;
    double avgDecapTime = static_cast<double>(totalDecapTime) / iterations;

    qDebug() << QString("Average encapsulation time: %1 ms").arg(avgEncapTime, 0, 'f', 3);
    qDebug() << QString("Average decapsulation time: %1 ms").arg(avgDecapTime, 0, 'f', 3);
    qDebug() << QString("Encapsulations per second: %1").arg(1000.0 / avgEncapTime, 0, 'f', 1);
    qDebug() << QString("Decapsulations per second: %1").arg(1000.0 / avgDecapTime, 0, 'f', 1);
}

/**
 * @brief Run memory usage analysis
 */
void analyzeMemoryUsage()
{
    qDebug() << "\n=== Memory Usage Analysis ===";

    // Key sizes (approximate)
    qDebug() << "Kyber-1024 key sizes:";
    qDebug() << QString("  Public key: %1 bytes (%2 KB)")
                .arg(OQS_KEM_kyber_1024_length_public_key)
                .arg(OQS_KEM_kyber_1024_length_public_key / 1024.0, 0, 'f', 2);
    qDebug() << QString("  Secret key: %1 bytes (%2 KB)")
                .arg(OQS_KEM_kyber_1024_length_secret_key)
                .arg(OQS_KEM_kyber_1024_length_secret_key / 1024.0, 0, 'f', 2);
    qDebug() << QString("  Ciphertext: %1 bytes (%2 KB)")
                .arg(OQS_KEM_kyber_1024_length_ciphertext)
                .arg(OQS_KEM_kyber_1024_length_ciphertext / 1024.0, 0, 'f', 2);
    qDebug() << QString("  Shared secret: %1 bytes")
                .arg(OQS_KEM_kyber_1024_length_shared_secret);

    qDebug() << "\nML-DSA-65 key sizes:";
    qDebug() << QString("  Public key: %1 bytes (%2 KB)")
                .arg(OQS_SIG_ml_dsa_65_length_public_key)
                .arg(OQS_SIG_ml_dsa_65_length_public_key / 1024.0, 0, 'f', 2);
    qDebug() << QString("  Secret key: %1 bytes (%2 KB)")
                .arg(OQS_SIG_ml_dsa_65_length_secret_key)
                .arg(OQS_SIG_ml_dsa_65_length_secret_key / 1024.0, 0, 'f', 2);
    qDebug() << QString("  Signature: ~%1 bytes (%2 KB)")
                .arg(OQS_SIG_ml_dsa_65_length_signature)
                .arg(OQS_SIG_ml_dsa_65_length_signature / 1024.0, 0, 'f', 2);
}

/**
 * @brief Main benchmark function
 */
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qDebug() << "🚀 Cybou Cryptographic Performance Benchmark";
    qDebug() << "==========================================";

    // Initialize crypto modules
    KeyManager keyManager;
    EncryptionEngine encryptionEngine(&keyManager);
    SignatureEngine signatureEngine(&keyManager);

    // Generate keys for testing
    qDebug() << "\n🔑 Generating test keys...";
    if (!keyManager.generateKeyPair()) {
        qDebug() << "❌ Failed to generate keys for benchmarking!";
        return 1;
    }
    qDebug() << "✅ Keys generated successfully";

    // Run benchmarks
    benchmarkKeyGeneration();
    benchmarkTextEncryption(&keyManager, &encryptionEngine);
    benchmarkFileEncryption(&keyManager, &encryptionEngine);
    benchmarkSignatures(&keyManager, &signatureEngine);
    benchmarkKeyEncapsulation(&keyManager, &signatureEngine);
    analyzeMemoryUsage();

    qDebug() << "\n🏁 Benchmarking completed!";
    qDebug() << "Note: Performance may vary based on hardware and liboqs optimization level.";

    return 0;
}