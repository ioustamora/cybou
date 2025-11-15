/**
 * @file test_encryptionengine.cpp
 * @brief Unit tests for EncryptionEngine module
 *
 * Tests text and file encryption/decryption functionality
 * of the EncryptionEngine class.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QTest>
#include <QTemporaryFile>
#include <QDir>
#include "src/crypto/KeyManager.h"
#include "src/crypto/EncryptionEngine.h"

/**
 * @class TestEncryptionEngine
 * @brief Unit test class for EncryptionEngine functionality
 */
class TestEncryptionEngine : public QObject
{
    Q_OBJECT

private:
    KeyManager *keyManager;
    EncryptionEngine *encryptionEngine;

private slots:
    /**
     * @brief Initialize test case
     */
    void initTestCase()
    {
        keyManager = new KeyManager();
        encryptionEngine = new EncryptionEngine(keyManager);

        // Generate keys for testing
        QVERIFY(keyManager->generateKeyPair());
    }

    /**
     * @brief Cleanup test case
     */
    void cleanupTestCase()
    {
        delete encryptionEngine;
        delete keyManager;
    }

    /**
     * @brief Test text encryption/decryption round-trip
     */
    void testTextEncryptionRoundTrip()
    {
        QString originalText = "Hello, quantum world! This is a test message for encryption.";
        qDebug() << "Original text:" << originalText;

        // Encrypt text
        QString encrypted = encryptionEngine->encryptText(originalText);
        QVERIFY(!encrypted.isEmpty());
        QVERIFY(encrypted != originalText); // Should be different
        qDebug() << "Encrypted:" << encrypted;

        // Decrypt text
        QString decrypted = encryptionEngine->decryptText(encrypted);
        QVERIFY(!decrypted.isEmpty());
        QCOMPARE(decrypted, originalText); // Should match original
        qDebug() << "Decrypted:" << decrypted;
    }

    /**
     * @brief Test text encryption with empty input
     */
    void testEmptyTextEncryption()
    {
        QString emptyText = "";

        // Encrypt empty text
        QString encrypted = encryptionEngine->encryptText(emptyText);
        QVERIFY(!encrypted.isEmpty()); // Should still produce output

        // Decrypt empty text
        QString decrypted = encryptionEngine->decryptText(encrypted);
        QCOMPARE(decrypted, emptyText); // Should match original empty string
    }

    /**
     * @brief Test text encryption with special characters
     */
    void testSpecialCharacters()
    {
        QString specialText = "Special chars: àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ ¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿";

        // Encrypt special characters
        QString encrypted = encryptionEngine->encryptText(specialText);
        QVERIFY(!encrypted.isEmpty());

        // Decrypt and verify
        QString decrypted = encryptionEngine->decryptText(encrypted);
        QCOMPARE(decrypted, specialText);
    }

    /**
     * @brief Test binary data encryption/decryption
     */
    void testBinaryDataEncryption()
    {
        // Create binary data with null bytes and special patterns
        QByteArray originalData;
        originalData.append("Text data");
        originalData.append('\0'); // Null byte
        originalData.append("More text");
        originalData.append('\0');
        originalData.append(QByteArray(100, '\xFF')); // Binary data

        // Encrypt binary data
        QByteArray encrypted = encryptionEngine->encryptBinary(originalData);
        QVERIFY(!encrypted.isEmpty());
        QVERIFY(encrypted.size() > originalData.size()); // Should include IV

        // Decrypt binary data
        QByteArray decrypted = encryptionEngine->decryptBinary(encrypted);
        QCOMPARE(decrypted, originalData);
    }

    /**
     * @brief Test file encryption/decryption round-trip
     */
    void testFileEncryptionRoundTrip()
    {
        // Create temporary test file
        QTemporaryFile testFile;
        QVERIFY(testFile.open());

        QString testContent = "This is test file content for encryption testing.\nWith multiple lines.\nAnd special chars: àáâãäå";
        testFile.write(testContent.toUtf8());
        testFile.close();

        QString inputPath = testFile.fileName();
        QString outputPath = inputPath + ".cybou";

        // Encrypt file
        bool encryptResult = encryptionEngine->encryptFile(inputPath, outputPath);
        QVERIFY(encryptResult);

        // Verify encrypted file exists
        QFileInfo encryptedFile(outputPath);
        QVERIFY(encryptedFile.exists());
        QVERIFY(encryptedFile.size() > 0);

        // Decrypt file
        QString decryptOutputPath = inputPath + "_decrypted.txt";
        bool decryptResult = encryptionEngine->decryptFile(outputPath, decryptOutputPath);
        QVERIFY(decryptResult);

        // Verify decrypted content matches original
        QFile decryptedFile(decryptOutputPath);
        QVERIFY(decryptedFile.open(QIODevice::ReadOnly));
        QString decryptedContent = QString::fromUtf8(decryptedFile.readAll());
        decryptedFile.close();

        QCOMPARE(decryptedContent, testContent);

        // Clean up
        QFile::remove(outputPath);
        QFile::remove(decryptOutputPath);
    }

    /**
     * @brief Test file encryption with non-existent input file
     */
    void testFileEncryptionNonExistentInput()
    {
        QString nonExistentFile = "/non/existent/file.txt";
        QString outputPath = "/tmp/output.cybou";

        bool result = encryptionEngine->encryptFile(nonExistentFile, outputPath);
        QVERIFY(!result);
    }

    /**
     * @brief Test file decryption with invalid encrypted file
     */
    void testFileDecryptionInvalidInput()
    {
        // Create temporary file with invalid content
        QTemporaryFile invalidFile;
        QVERIFY(invalidFile.open());
        invalidFile.write("This is not a valid encrypted file");
        invalidFile.close();

        QString inputPath = invalidFile.fileName();
        QString outputPath = inputPath + "_decrypted.txt";

        bool result = encryptionEngine->decryptFile(inputPath, outputPath);
        QVERIFY(!result);
    }

    /**
     * @brief Test text file save/load operations
     */
    void testTextFileOperations()
    {
        QString testContent = "Test content for file operations";

        // Create temporary file path
        QTemporaryFile tempFile;
        tempFile.setAutoRemove(false);
        tempFile.open();
        QString filePath = tempFile.fileName();
        tempFile.close();

        // Save text to file
        bool saveResult = encryptionEngine->saveTextToFile(testContent, filePath);
        QVERIFY(saveResult);

        // Load text from file
        QString loadedContent = encryptionEngine->loadTextFromFile(filePath);
        QCOMPARE(loadedContent, testContent);

        // Clean up
        QFile::remove(filePath);
    }

    /**
     * @brief Test encryption without keys
     */
    void testEncryptionWithoutKeys()
    {
        // Create engine without keys
        KeyManager keylessManager;
        EncryptionEngine keylessEngine(&keylessManager);

        QString testText = "Test without keys";

        // Operations should fail gracefully
        QString encrypted = keylessEngine.encryptText(testText);
        QVERIFY(encrypted.isEmpty());

        QString decrypted = keylessEngine.decryptText("invalid");
        QVERIFY(decrypted.isEmpty());
    }
};

/**
 * @brief Main test function
 */
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qDebug() << "Running EncryptionEngine unit tests...";

    TestEncryptionEngine test;
    int result = QTest::qExec(&test, argc, argv);

    if (result == 0) {
        qDebug() << "✅ All EncryptionEngine tests passed!";
    } else {
        qDebug() << "❌ EncryptionEngine tests failed!";
    }

    return result;
}

#include "test_encryptionengine.moc"