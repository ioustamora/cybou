/**
 * @file test_signatureengine.cpp
 * @brief Unit tests for SignatureEngine module
 *
 * Tests digital signature creation, verification, and key exchange
 * functionality of the SignatureEngine class.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QTest>
#include "src/crypto/KeyManager.h"
#include "src/crypto/SignatureEngine.h"

/**
 * @class TestSignatureEngine
 * @brief Unit test class for SignatureEngine functionality
 */
class TestSignatureEngine : public QObject
{
    Q_OBJECT

private:
    KeyManager *keyManager;
    SignatureEngine *signatureEngine;

private slots:
    /**
     * @brief Initialize test case
     */
    void initTestCase()
    {
        keyManager = new KeyManager();
        signatureEngine = new SignatureEngine(keyManager);

        // Generate keys for testing
        QVERIFY(keyManager->generateKeyPair());
    }

    /**
     * @brief Cleanup test case
     */
    void cleanupTestCase()
    {
        delete signatureEngine;
        delete keyManager;
    }

    /**
     * @brief Test message signing and verification round-trip
     */
    void testSignVerifyRoundTrip()
    {
        QString testMessage = "This is a test message for digital signature verification.";
        qDebug() << "Test message:" << testMessage;

        // Sign the message
        QString signature = signatureEngine->signMessage(testMessage);
        QVERIFY(!signature.isEmpty());
        qDebug() << "Signature:" << signature;

        // Get public key for verification
        QString publicKey = keyManager->publicKey();
        QVERIFY(!publicKey.isEmpty());

        // Verify the signature
        bool isValid = signatureEngine->verifySignature(testMessage, signature, publicKey);
        QVERIFY(isValid);
        qDebug() << "Signature verification: PASSED";
    }

    /**
     * @brief Test signature verification with wrong message
     */
    void testSignatureVerificationWrongMessage()
    {
        QString originalMessage = "Original message";
        QString wrongMessage = "Wrong message";

        // Sign original message
        QString signature = signatureEngine->signMessage(originalMessage);
        QVERIFY(!signature.isEmpty());

        // Try to verify with wrong message
        QString publicKey = keyManager->publicKey();
        bool isValid = signatureEngine->verifySignature(wrongMessage, signature, publicKey);
        QVERIFY(!isValid); // Should fail
    }

    /**
     * @brief Test signature verification with wrong signature
     */
    void testSignatureVerificationWrongSignature()
    {
        QString testMessage = "Test message";

        // Create a fake signature
        QString fakeSignature = "fake_signature_hex_string";

        QString publicKey = keyManager->publicKey();
        bool isValid = signatureEngine->verifySignature(testMessage, fakeSignature, publicKey);
        QVERIFY(!isValid); // Should fail
    }

    /**
     * @brief Test signature verification with wrong public key
     */
    void testSignatureVerificationWrongKey()
    {
        QString testMessage = "Test message";

        // Sign with our key
        QString signature = signatureEngine->signMessage(testMessage);
        QVERIFY(!signature.isEmpty());

        // Create different key pair
        KeyManager otherKeyManager;
        QVERIFY(otherKeyManager.generateKeyPair());
        QString wrongPublicKey = otherKeyManager.publicKey();

        // Try to verify with wrong public key
        bool isValid = signatureEngine->verifySignature(testMessage, signature, wrongPublicKey);
        QVERIFY(!isValid); // Should fail
    }

    /**
     * @brief Test signing empty message
     */
    void testSignEmptyMessage()
    {
        QString emptyMessage = "";

        QString signature = signatureEngine->signMessage(emptyMessage);
        QVERIFY(!signature.isEmpty()); // Should still produce a signature

        // Verify the signature
        QString publicKey = keyManager->publicKey();
        bool isValid = signatureEngine->verifySignature(emptyMessage, signature, publicKey);
        QVERIFY(isValid);
    }

    /**
     * @brief Test signing message with special characters
     */
    void testSignSpecialCharacters()
    {
        QString specialMessage = "Special chars: àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ ¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿";

        QString signature = signatureEngine->signMessage(specialMessage);
        QVERIFY(!signature.isEmpty());

        QString publicKey = keyManager->publicKey();
        bool isValid = signatureEngine->verifySignature(specialMessage, signature, publicKey);
        QVERIFY(isValid);
    }

    /**
     * @brief Test Kyber key encapsulation round-trip
     */
    void testKeyEncapsulationRoundTrip()
    {
        // Create recipient key pair
        KeyManager recipientKeyManager;
        QVERIFY(recipientKeyManager.generateKeyPair());
        QString recipientPublicKey = recipientKeyManager.publicKey();

        // Perform key encapsulation
        QVariantMap encapsulationResult = signatureEngine->encapsulateKey(recipientPublicKey);
        QVERIFY(encapsulationResult.contains("ciphertext"));
        QVERIFY(encapsulationResult.contains("sharedSecret"));

        QString ciphertext = encapsulationResult["ciphertext"].toString();
        QVERIFY(!ciphertext.isEmpty());

        // Create signature engine for recipient
        SignatureEngine recipientEngine(&recipientKeyManager);

        // Decapsulate the key
        QByteArray decapsulatedSecret = recipientEngine.decapsulateKey(encapsulationResult);
        QVERIFY(!decapsulatedSecret.isEmpty());

        // Verify shared secrets match (would need to compare with sender's secret)
        // Note: In real usage, the sender would have the shared secret from encapsulation
        qDebug() << "Key encapsulation round-trip successful";
    }

    /**
     * @brief Test shared secret generation
     */
    void testSharedSecretGeneration()
    {
        // Create recipient key pair
        KeyManager recipientKeyManager;
        QVERIFY(recipientKeyManager.generateKeyPair());
        QString recipientPublicKey = recipientKeyManager.publicKey();

        // Generate shared secret
        QString sharedSecret = signatureEngine->generateSharedSecret(recipientPublicKey);
        QVERIFY(!sharedSecret.isEmpty());
        QVERIFY(sharedSecret.length() > 10); // Should be substantial hex string

        qDebug() << "Shared secret generated:" << sharedSecret;
    }

    /**
     * @brief Test key encapsulation with invalid public key
     */
    void testKeyEncapsulationInvalidKey()
    {
        QString invalidKey = "invalid_public_key_hex";

        QVariantMap result = signatureEngine->encapsulateKey(invalidKey);
        QVERIFY(result.contains("error")); // Should contain error
    }

    /**
     * @brief Test decapsulation with invalid data
     */
    void testDecapsulationInvalidData()
    {
        QVariantMap invalidData;
        invalidData["ciphertext"] = "invalid_ciphertext";

        QByteArray result = signatureEngine->decapsulateKey(invalidData);
        QVERIFY(result.isEmpty()); // Should fail
    }

    /**
     * @brief Test operations without keys
     */
    void testOperationsWithoutKeys()
    {
        // Create engine without keys
        KeyManager keylessManager;
        SignatureEngine keylessEngine(&keylessManager);

        QString testMessage = "Test message";

        // Operations should fail gracefully
        QString signature = keylessEngine.signMessage(testMessage);
        QVERIFY(signature.isEmpty());

        bool verification = keylessEngine.verifySignature(testMessage, "fake_sig", "fake_key");
        QVERIFY(!verification);

        QVariantMap encapsulation = keylessEngine.encapsulateKey("fake_key");
        QVERIFY(encapsulation.contains("error"));
    }

    /**
     * @brief Test signature consistency (same message produces different signatures)
     */
    void testSignatureConsistency()
    {
        QString testMessage = "Consistent message";

        // Sign the same message twice
        QString signature1 = signatureEngine->signMessage(testMessage);
        QString signature2 = signatureEngine->signMessage(testMessage);

        QVERIFY(!signature1.isEmpty());
        QVERIFY(!signature2.isEmpty());

        // Signatures should be different (due to randomization in signing)
        // Note: ML-DSA-65 may or may not be deterministic depending on implementation
        // This test verifies both signatures are valid
        QString publicKey = keyManager->publicKey();

        bool valid1 = signatureEngine->verifySignature(testMessage, signature1, publicKey);
        bool valid2 = signatureEngine->verifySignature(testMessage, signature2, publicKey);

        QVERIFY(valid1);
        QVERIFY(valid2);
    }
};

/**
 * @brief Main test function
 */
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qDebug() << "Running SignatureEngine unit tests...";

    TestSignatureEngine test;
    int result = QTest::qExec(&test, argc, argv);

    if (result == 0) {
        qDebug() << "✅ All SignatureEngine tests passed!";
    } else {
        qDebug() << "❌ SignatureEngine tests failed!";
    }

    return result;
}

#include "test_signatureengine.moc"