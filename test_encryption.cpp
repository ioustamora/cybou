/**
 * @file test_encryption.cpp
 * @brief Test suite for post-quantum encryption functionality
 *
 * This test validates the core encryption/decryption round-trip functionality
 * of the PostQuantumCrypto class. It ensures that:
 * - Key pair generation works correctly
 * - Text encryption produces valid ciphertext
 * - Text decryption recovers the original plaintext
 * - The encrypt/decrypt process is deterministic and reversible
 *
 * The test uses a simple message and verifies that encryption followed by
 * decryption returns the original text, confirming the cryptographic
 * implementation is working correctly.
 */

#include <QCoreApplication>
#include <QDebug>
#include "src/crypto/PostQuantumCrypto.h"

/**
 * @brief Main test function for encryption/decryption round-trip
 *
 * Test procedure:
 * 1. Initialize Qt application
 * 2. Create PostQuantumCrypto instance
 * 3. Generate quantum-resistant key pairs
 * 4. Encrypt a test message
 * 5. Decrypt the ciphertext
 * 6. Verify the decrypted text matches the original
 *
 * @param argc Command line argument count
 * @param argv Command line arguments
 * @return int 0 on success, 1 on failure
 */
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    // Create the post-quantum crypto engine
    PostQuantumCrypto crypto;

    // Generate Kyber-1024 and ML-DSA-65 key pairs
    // This is required before any encryption operations
    if (!crypto.generateKeyPair()) {
        qDebug() << "Failed to generate keys";
        return 1;
    }

    // Test message for encryption/decryption validation
    QString originalText = "Hello, quantum world! This is a test message for cybou encryption.";
    qDebug() << "Original text:" << originalText;

    // Encrypt the test message using deterministic key derivation
    QString encrypted = crypto.encryptText(originalText);
    qDebug() << "Encrypted:" << encrypted;

    // Decrypt the ciphertext back to plaintext
    QString decrypted = crypto.decryptText(encrypted);
    qDebug() << "Decrypted:" << decrypted;

    // Verify the round-trip encryption/decryption worked correctly
    if (originalText == decrypted) {
        qDebug() << "SUCCESS: Encryption/decryption works correctly!";
        return 0; // Test passed
    } else {
        qDebug() << "FAILURE: Decrypted text doesn't match original!";
        return 1; // Test failed
    }
}
