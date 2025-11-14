/**
 * @file MnemonicEngine.cpp
 * @brief Implementation of BIP-39 mnemonic generation and validation
 *
 * This file contains the implementation of the MnemonicEngine class, providing
 * cryptographically secure BIP-39 mnemonic generation, validation, and key derivation.
 * The implementation uses the official BIP-39 word list and follows the specification
 * for entropy generation, checksum calculation, and word encoding.
 */

#include "MnemonicEngine.h"
#include "bip39_words.h"
#include "PostQuantumCrypto.h"

#include <QRandomGenerator>
#include <QFile>
#include <QTextStream>
#include <QCryptographicHash>
#include <QMap>
#include <QDebug>

QStringList MnemonicEngine::s_wordList;
bool MnemonicEngine::s_wordListLoaded = false;

/**
 * @brief Constructs a MnemonicEngine and loads the BIP-39 word list
 *
 * The constructor ensures the static BIP-39 word list is loaded from the
 * embedded word array. This happens only once for all instances of the class.
 *
 * @param parent Parent QObject for Qt's object hierarchy
 */
MnemonicEngine::MnemonicEngine(QObject *parent)
    : QObject(parent)
{
    if (!s_wordListLoaded) {
        // Load words from the static array defined in bip39_words.h
        // This contains all 2048 BIP-39 words in the correct order
        for (int i = 0; i < BIP39_WORD_COUNT; ++i) {
            s_wordList.append(QString::fromUtf8(BIP39_WORDS[i]));
        }
        s_wordListLoaded = true;
        qDebug() << "Loaded" << s_wordList.size() << "words from BIP-39 word list";
    }
}

/**
 * @brief Returns the static BIP-39 word list
 *
 * This method ensures the word list is loaded and returns a reference to it.
 * The dummy instance creation guarantees initialization on first access.
 *
 * @return const QStringList& Reference to the 2048-word BIP-39 list
 */
const QStringList &MnemonicEngine::wordList()
{
    static MnemonicEngine dummy; // Ensure word list is loaded
    return s_wordList;
}

/**
 * @brief Generates a BIP-39 compatible mnemonic phrase
 *
 * This function implements the complete BIP-39 algorithm for generating
 * cryptographically secure mnemonic phrases. The process follows these steps:
 *
 * 1. Generate entropy of the appropriate size for the word count
 * 2. Calculate a checksum using SHA-256 (entropy length / 32 bits)
 * 3. Concatenate entropy + checksum
 * 4. Split into 11-bit chunks and map to words from the 2048-word list
 *
 * Supported word counts: 12, 15, 18, 21, 24 (corresponding to 128-256 bits entropy)
 *
 * @param words Number of words in the mnemonic (default: 12)
 * @return QString The generated mnemonic phrase, or error message on failure
 */
QString MnemonicEngine::generateMnemonic(int words)
{
    // Validate word count - must be one of the BIP-39 supported values
    if (words != 12 && words != 15 && words != 18 && words != 21 && words != 24) {
        words = 12; // Default to 12 words if invalid count provided
    }

    // Ensure word list is available
    if (s_wordList.isEmpty()) {
        return QStringLiteral("Error: Word list not loaded");
    }

    // BIP-39 specification: entropy size determines word count
    // Each word represents 11 bits, checksum is entropy_bits/32
    static const QMap<int, int> entropyBitsMap = {
        {12, 128}, {15, 160}, {18, 192}, {21, 224}, {24, 256}
    };
    const int entropyBits = entropyBitsMap.value(words);
    const int checksumBits = entropyBits / 32; // Always results in 4, 5, 6, 7, or 8
    const int totalBits = entropyBits + checksumBits;

    // Generate cryptographically secure entropy
    // Calculate bytes needed (round up for partial bytes)
    const int entropyBytes = (entropyBits + 7) / 8; // Ceiling division
    QByteArray entropy(entropyBytes, 0);
    QRandomGenerator::global()->generate(entropy.begin(), entropy.end());

    // Truncate entropy to exact bit count if necessary
    // For example, 128 bits = 16 bytes, but 160 bits = 20 bytes + 4 bits from last byte
    if (entropyBits % 8 != 0) {
        // Mask the last byte to only use the required bits
        const int usedBitsInLastByte = entropyBits % 8;
        entropy[entropyBytes - 1] &= (0xFF << (8 - usedBitsInLastByte));
    }

    // Calculate checksum: SHA-256 of entropy, take first byte
    // Checksum provides error detection for the mnemonic
    QByteArray hash = QCryptographicHash::hash(entropy, QCryptographicHash::Sha256);
    const quint8 checksumByte = hash[0]; // First byte of SHA-256 hash

    // Build the complete binary string (entropy + checksum)
    // This creates a bit sequence that will be split into 11-bit chunks
    QString binaryString;

    // Convert entropy bytes to binary string (MSB first)
    for (int i = 0; i < entropyBytes; ++i) {
        quint8 byte = static_cast<quint8>(entropy[i]);
        for (int bit = 7; bit >= 0; --bit) {
            if (binaryString.length() < entropyBits) {
                binaryString += (byte & (1 << bit)) ? '1' : '0';
            }
        }
    }

    // Append checksum bits (MSB first from checksum byte)
    for (int bit = 7; bit >= 0; --bit) {
        if (binaryString.length() < totalBits) {
            binaryString += (checksumByte & (1 << bit)) ? '1' : '0';
        }
    }

    // Convert binary string to words (11 bits per word = 2048 possible words)
    QStringList tokens;
    for (int i = 0; i < words; ++i) {
        // Extract 11-bit chunk and convert to integer index
        const QString chunk = binaryString.mid(i * 11, 11);
        if (chunk.length() == 11) {
            bool ok;
            const int index = chunk.toInt(&ok, 2); // Binary string to int
            if (ok && index >= 0 && index < s_wordList.size()) {
                tokens << s_wordList[index]; // Map index to word
            } else {
                tokens << QStringLiteral("error_%1").arg(index);
            }
        } else {
            tokens << QStringLiteral("chunk_error");
        }
    }

    // Store and emit the generated mnemonic
    m_currentMnemonic = tokens.join(QLatin1Char(' '));
    emit mnemonicChanged();
    return m_currentMnemonic;
}

/**
 * @brief Validates a mnemonic phrase against BIP-39 rules
 *
 * Performs basic validation of a mnemonic phrase:
 * - Checks that the word count is valid (12, 15, 18, 21, or 24)
 * - Verifies all words are present in the BIP-39 word list
 *
 * Note: Full checksum validation is not yet implemented (TODO).
 * Currently only validates vocabulary and word count.
 *
 * @param mnemonic The mnemonic phrase to validate
 * @return bool True if the mnemonic passes basic validation
 */
bool MnemonicEngine::validateMnemonic(const QString &mnemonic) const
{
    const QString trimmed = mnemonic.trimmed();
    if (trimmed.isEmpty())
        return false;

    const QStringList parts = trimmed.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    const int wordCount = parts.size();

    // Check for valid BIP-39 word counts
    if (wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24) {
        return false; // Invalid word count
    }

    // Verify all words exist in the BIP-39 word list
    for (const QString &word : parts) {
        if (!s_wordList.contains(word)) {
            return false;
        }
    }

    // TODO: Implement full BIP-39 checksum validation
    // This would involve reversing the generation process to verify
    // that the checksum matches the entropy
    return true;
}

/**
 * @brief Sets and validates a mnemonic phrase
 *
 * If the mnemonic is valid, stores it and automatically:
 * - Derives a key from the mnemonic
 * - Generates post-quantum key pairs (if PQ crypto is connected)
 * - Emits the mnemonicChanged signal
 *
 * @param mnemonic The mnemonic phrase to set
 * @return bool True if the mnemonic was set successfully
 */
bool MnemonicEngine::setMnemonic(const QString &mnemonic)
{
    if (validateMnemonic(mnemonic)) {
        m_currentMnemonic = mnemonic.trimmed();
        emit mnemonicChanged();
        deriveKeyFromMnemonic(); // Auto-derive key when mnemonic is set

        // Auto-generate PQ keys when mnemonic is set
        if (m_pqCrypto) {
            m_pqCrypto->generateKeyPair();
        }

        return true;
    }
    return false;
}

/**
 * @brief Derives a cryptographic key from the current mnemonic
 *
 * Implements a simplified key derivation function similar to PBKDF2:
 * - Uses the mnemonic as initial seed material
 * - Applies 2048 rounds of SHA-256 hashing (same iteration count as PBKDF2)
 * - Takes the first 32 bytes as the final key
 *
 * Note: This is a demonstration implementation. A production version would
 * use proper BIP-39 seed generation followed by HKDF for key derivation.
 *
 * @param passphrase Optional passphrase for additional entropy (currently unused)
 */
void MnemonicEngine::deriveKeyFromMnemonic(const QString &passphrase)
{
    if (m_currentMnemonic.isEmpty()) {
        m_derivedKeyHex = QString();
        emit keyDerived();
        return;
    }

    // Simple PBKDF2-like derivation for demonstration
    // In a real implementation, this would use proper BIP-39 seed generation
    // followed by post-quantum key derivation

    QByteArray seed = m_currentMnemonic.toUtf8();
    if (!passphrase.isEmpty()) {
        seed += passphrase.toUtf8();
    }

    // Simple key derivation: hash the seed multiple times
    // This provides computational cost similar to PBKDF2
    QByteArray derivedKey = seed;
    for (int i = 0; i < 2048; ++i) { // 2048 iterations like PBKDF2
        derivedKey = QCryptographicHash::hash(derivedKey, QCryptographicHash::Sha256);
    }

    // Take first 32 bytes as the key (256 bits)
    derivedKey = derivedKey.left(32);

    m_derivedKeyHex = derivedKey.toHex().toUpper();
    emit keyDerived();
}
