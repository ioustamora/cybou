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

MnemonicEngine::MnemonicEngine(QObject *parent)
    : QObject(parent)
{
    if (!s_wordListLoaded) {
        // Load words from the static array
        for (int i = 0; i < BIP39_WORD_COUNT; ++i) {
            s_wordList.append(QString::fromUtf8(BIP39_WORDS[i]));
        }
        s_wordListLoaded = true;
        qDebug() << "Loaded" << s_wordList.size() << "words from BIP-39 word list";
    }
}

const QStringList &MnemonicEngine::wordList()
{
    static MnemonicEngine dummy; // Ensure word list is loaded
    return s_wordList;
}

QString MnemonicEngine::generateMnemonic(int words)
{
    if (words != 12 && words != 15 && words != 18 && words != 21 && words != 24) {
        words = 12; // Default to 12 words
    }

    if (s_wordList.isEmpty()) {
        return QStringLiteral("Error: Word list not loaded");
    }

    // BIP-39 entropy sizes (in bits)
    static const QMap<int, int> entropyBitsMap = {
        {12, 128}, {15, 160}, {18, 192}, {21, 224}, {24, 256}
    };
    const int entropyBits = entropyBitsMap.value(words);
    const int checksumBits = entropyBits / 32; // Always 4, 5, 6, 7, or 8
    const int totalBits = entropyBits + checksumBits;

    // Generate exact entropy bytes needed
    const int entropyBytes = (entropyBits + 7) / 8; // Round up
    QByteArray entropy(entropyBytes, 0);
    QRandomGenerator::global()->generate(entropy.begin(), entropy.end());

    // Truncate entropy to exact bits if necessary
    if (entropyBits % 8 != 0) {
        // Mask the last byte to only use the required bits
        const int usedBitsInLastByte = entropyBits % 8;
        entropy[entropyBytes - 1] &= (0xFF << (8 - usedBitsInLastByte));
    }

    // Calculate checksum
    QByteArray hash = QCryptographicHash::hash(entropy, QCryptographicHash::Sha256);
    const quint8 checksumByte = hash[0]; // First byte of hash

    // Build the complete binary string (entropy + checksum)
    QString binaryString;
    // Add entropy bits
    for (int i = 0; i < entropyBytes; ++i) {
        quint8 byte = static_cast<quint8>(entropy[i]);
        for (int bit = 7; bit >= 0; --bit) {
            if (binaryString.length() < entropyBits) {
                binaryString += (byte & (1 << bit)) ? '1' : '0';
            }
        }
    }
    // Add checksum bits
    for (int bit = 7; bit >= 0; --bit) {
        if (binaryString.length() < totalBits) {
            binaryString += (checksumByte & (1 << bit)) ? '1' : '0';
        }
    }

    // Convert to words (11 bits per word)
    QStringList tokens;
    for (int i = 0; i < words; ++i) {
        const QString chunk = binaryString.mid(i * 11, 11);
        if (chunk.length() == 11) {
            bool ok;
            const int index = chunk.toInt(&ok, 2);
            if (ok && index >= 0 && index < s_wordList.size()) {
                tokens << s_wordList[index];
            } else {
                tokens << QStringLiteral("error_%1").arg(index);
            }
        } else {
            tokens << QStringLiteral("chunk_error");
        }
    }

    m_currentMnemonic = tokens.join(QLatin1Char(' '));
    emit mnemonicChanged();
    return m_currentMnemonic;
}

bool MnemonicEngine::validateMnemonic(const QString &mnemonic) const
{
    const QString trimmed = mnemonic.trimmed();
    if (trimmed.isEmpty())
        return false;

    const QStringList parts = trimmed.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    const int wordCount = parts.size();

    if (wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24) {
        return false; // Invalid word count
    }

    // Check all words are in the word list
    for (const QString &word : parts) {
        if (!s_wordList.contains(word)) {
            return false;
        }
    }

    // TODO: Implement full BIP-39 checksum validation
    // For now, just check word count and vocabulary
    return true;
}

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
    QByteArray derivedKey = seed;
    for (int i = 0; i < 2048; ++i) { // 2048 iterations like PBKDF2
        derivedKey = QCryptographicHash::hash(derivedKey, QCryptographicHash::Sha256);
    }

    // Take first 32 bytes as the key
    derivedKey = derivedKey.left(32);

    m_derivedKeyHex = derivedKey.toHex().toUpper();
    emit keyDerived();
}
