/**
 * @file test_keymanager.cpp
 * @brief Unit tests for KeyManager module
 *
 * Tests key generation, import/export, and deterministic key derivation
 * functionality of the KeyManager class.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QTest>
#include "src/crypto/KeyManager.h"
#include "src/crypto/PostQuantumCrypto.h"

/**
 * @class TestKeyManager
 * @brief Unit test class for KeyManager functionality
 */
class TestKeyManager : public QObject
{
    Q_OBJECT

private slots:
    /**
     * @brief Test key pair generation
     */
    void testKeyGeneration()
    {
        KeyManager keyManager;

        // Test key generation
        QVERIFY(keyManager.generateKeyPair());
        QVERIFY(keyManager.hasKeys());

        // Test public key is not empty
        QString publicKey = keyManager.publicKey();
        QVERIFY(!publicKey.isEmpty());
        QVERIFY(publicKey.length() > 100); // Should be substantial hex string

        // Test algorithm string
        QString algorithm = keyManager.keyAlgorithm();
        QVERIFY(algorithm.contains("Kyber"));
        QVERIFY(algorithm.contains("ML-DSA"));
    }

    /**
     * @brief Test key import/export round-trip
     */
    void testKeyImportExport()
    {
        KeyManager keyManager1;
        KeyManager keyManager2;

        // Generate keys in first manager
        QVERIFY(keyManager1.generateKeyPair());
        QString originalPublicKey = keyManager1.publicKey();

        // Export keys
        QString exportedPrivateKey = keyManager1.exportPrivateKey();
        QString exportedPublicKey = keyManager1.exportPublicKey();

        QVERIFY(!exportedPrivateKey.isEmpty());
        QVERIFY(!exportedPublicKey.isEmpty());

        // Import keys into second manager
        QVERIFY(keyManager2.importKeyPair(exportedPrivateKey, exportedPublicKey));

        // Verify imported keys match
        QString importedPublicKey = keyManager2.publicKey();
        QCOMPARE(importedPublicKey, originalPublicKey);

        // Verify both managers have keys
        QVERIFY(keyManager1.hasKeys());
        QVERIFY(keyManager2.hasKeys());
    }

    /**
     * @brief Test deterministic key derivation
     */
    void testDeterministicKeyDerivation()
    {
        KeyManager keyManager;

        // Generate keys
        QVERIFY(keyManager.generateKeyPair());

        // Get deterministic key
        QByteArray key1 = keyManager.generateDeterministicKey();
        QByteArray key2 = keyManager.generateDeterministicKey();

        // Keys should be deterministic (same input produces same output)
        QCOMPARE(key1, key2);
        QCOMPARE(key1.size(), 32); // Should be 256 bits

        // Test with different key pairs produce different keys
        KeyManager keyManager2;
        QVERIFY(keyManager2.generateKeyPair());
        QByteArray key3 = keyManager2.generateDeterministicKey();

        QVERIFY(key1 != key3); // Different key pairs should produce different keys
    }

    /**
     * @brief Test invalid key import handling
     */
    void testInvalidKeyImport()
    {
        KeyManager keyManager;

        // Test with empty strings
        QVERIFY(!keyManager.importKeyPair("", ""));

        // Test with invalid hex
        QVERIFY(!keyManager.importKeyPair("invalid", "hex"));

        // Test with wrong lengths
        QVERIFY(!keyManager.importKeyPair("12345678", "87654321"));

        // Verify no keys were imported
        QVERIFY(!keyManager.hasKeys());
    }

    /**
     * @brief Test key export without keys
     */
    void testExportWithoutKeys()
    {
        KeyManager keyManager;

        // Should return empty strings when no keys
        QVERIFY(keyManager.exportPrivateKey().isEmpty());
        QVERIFY(keyManager.exportPublicKey().isEmpty());
        QVERIFY(keyManager.publicKey().isEmpty());
    }

    /**
     * @brief Test key cleanup and regeneration
     */
    void testKeyCleanup()
    {
        KeyManager keyManager;

        // Generate initial keys
        QVERIFY(keyManager.generateKeyPair());
        QString key1 = keyManager.publicKey();
        QVERIFY(!key1.isEmpty());

        // Generate new keys (should replace old ones)
        QVERIFY(keyManager.generateKeyPair());
        QString key2 = keyManager.publicKey();
        QVERIFY(!key2.isEmpty());

        // New keys should be different from old ones
        QVERIFY(key1 != key2);
    }
};

/**
 * @brief Main test function
 */
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qDebug() << "Running KeyManager unit tests...";

    TestKeyManager test;
    int result = QTest::qExec(&test, argc, argv);

    if (result == 0) {
        qDebug() << "✅ All KeyManager tests passed!";
    } else {
        qDebug() << "❌ KeyManager tests failed!";
    }

    return result;
}

#include "test_keymanager.moc"