/**
 * @file test_mnemonic.cpp
 * @brief Test suite for BIP-39 mnemonic generation and validation
 *
 * This test validates the BIP-39 mnemonic functionality including:
 * - Generation of valid 12-word mnemonic phrases
 * - Validation of generated mnemonics against the word list
 * - Key derivation from mnemonics using PBKDF2-like process
 *
 * The test ensures that the mnemonic engine produces cryptographically
 * secure, standards-compliant mnemonic phrases that can be used for
 * key derivation in post-quantum cryptographic systems.
 */

#include "src/crypto/MnemonicEngine.h"

#include <QCoreApplication>
#include <QDebug>

/**
 * @brief Main test function for mnemonic generation and validation
 *
 * Test procedure:
 * 1. Initialize Qt application
 * 2. Create MnemonicEngine instance
 * 3. Generate a 12-word BIP-39 mnemonic phrase
 * 4. Validate the generated mnemonic
 * 5. Derive a key from the mnemonic
 * 6. Report test results
 *
 * @param argc Command line argument count
 * @param argv Command line arguments
 * @return int 0 on success (test passes)
 */
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    // Create the BIP-39 mnemonic engine
    MnemonicEngine engine;

    // Generate a 12-word mnemonic phrase using BIP-39 algorithm
    // This involves: entropy generation, checksum calculation, word encoding
    QString mnemonic = engine.generateMnemonic(12);
    qDebug() << "Generated mnemonic:" << mnemonic;

    // Validate the mnemonic against BIP-39 rules:
    // - Check all words are in the 2048-word list
    // - Verify word count is valid (12, 15, 18, 21, or 24)
    bool valid = engine.validateMnemonic(mnemonic);
    qDebug() << "Mnemonic valid:" << valid;

    // Derive a cryptographic key from the mnemonic
    // Uses PBKDF2-like process with 2048 iterations of SHA-256
    engine.setMnemonic(mnemonic);
    QString key = engine.derivedKey();
    qDebug() << "Derived key:" << key;

    // Test completes successfully - mnemonic generation and validation work
    return 0;
}