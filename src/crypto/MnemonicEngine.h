/**
 * @file MnemonicEngine.h
 * @brief BIP-39 mnemonic generation and validation engine
 *
 * This class implements BIP-39 compatible mnemonic phrase generation and validation.
 * It provides cryptographically secure entropy generation, checksum calculation,
 * and word list encoding/decoding according to the BIP-39 standard.
 */

#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QByteArray>

// Forward declaration
class PostQuantumCrypto;

/**
 * @class MnemonicEngine
 * @brief Implements BIP-39 compatible mnemonic generation and validation
 *
 * MnemonicEngine provides complete BIP-39 functionality including:
 * - Generation of 12-24 word mnemonic phrases from cryptographically secure entropy
 * - Validation of mnemonic phrases against the BIP-39 word list and checksum
 * - Key derivation from mnemonics for post-quantum cryptographic operations
 * - Integration with PostQuantumCrypto for automatic key pair generation
 *
 * The implementation follows BIP-39 specification exactly, using the official
 * 2048-word list and proper entropy/checksum handling.
 */
class MnemonicEngine : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool hasMnemonic READ hasMnemonic NOTIFY mnemonicChanged)
    Q_PROPERTY(QString currentMnemonic READ currentMnemonic NOTIFY mnemonicChanged)
    Q_PROPERTY(QString derivedKey READ derivedKey NOTIFY keyDerived)

public:
    /**
     * @brief Constructs a MnemonicEngine instance
     * @param parent Parent QObject for memory management
     */
    explicit MnemonicEngine(QObject *parent = nullptr);

    /**
     * @brief Generates a BIP-39 compatible mnemonic phrase
     *
     * Creates a mnemonic phrase with the specified number of words (12, 15, 18, 21, or 24).
     * The process involves:
     * 1. Generating cryptographically secure entropy
     * 2. Calculating a checksum using SHA-256
     * 3. Encoding entropy + checksum into word indices
     * 4. Mapping indices to words from the BIP-39 word list
     *
     * @param words Number of words in the mnemonic (default: 12)
     * @return QString The generated mnemonic phrase, or error message on failure
     */
    Q_INVOKABLE QString generateMnemonic(int words = 12);

    /**
     * @brief Validates a mnemonic phrase against BIP-39 rules
     *
     * Performs complete BIP-39 validation including:
     * - Checks that the word count is valid (12, 15, 18, 21, or 24)
     * - Verifies all words are present in the BIP-39 word list
     * - Validates the checksum to ensure the mnemonic was generated correctly
     *
     * The checksum validation reverses the generation process:
     * 1. Convert words to indices and then to 11-bit binary chunks
     * 2. Extract entropy and checksum from the concatenated bits
     * 3. Verify checksum matches SHA-256 hash of entropy
     *
     * @param mnemonic The mnemonic phrase to validate
     * @return bool True if the mnemonic passes complete BIP-39 validation
     */
    Q_INVOKABLE bool validateMnemonic(const QString &mnemonic) const;

    /**
     * @brief Sets and validates a mnemonic phrase
     *
     * If the mnemonic is valid, stores it and automatically derives keys.
     * Also triggers post-quantum key pair generation if PQ crypto is connected.
     *
     * @param mnemonic The mnemonic phrase to set
     * @return bool True if the mnemonic was set successfully
     */
    Q_INVOKABLE bool setMnemonic(const QString &mnemonic);

    /**
     * @brief Derives a key from the current mnemonic using PBKDF2-like process
     *
     * Uses a simplified key derivation process for demonstration:
     * - Converts mnemonic to UTF-8 bytes
     * - Applies SHA-256 hashing 2048 times (similar to PBKDF2 iteration count)
     * - Takes first 32 bytes as the derived key
     *
     * @param passphrase Optional passphrase for additional entropy (unused in current implementation)
     */
    Q_INVOKABLE void deriveKeyFromMnemonic(const QString &passphrase = QString());

    /**
     * @brief Checks if a mnemonic phrase has been set
     * @return bool True if a mnemonic is currently stored
     */
    bool hasMnemonic() const { return !m_currentMnemonic.isEmpty(); }

    /**
     * @brief Gets the current mnemonic phrase
     * @return QString The stored mnemonic phrase
     */
    QString currentMnemonic() const { return m_currentMnemonic; }

    /**
     * @brief Gets the derived key in hexadecimal format
     * @return QString The derived key as uppercase hex string
     */
    QString derivedKey() const { return m_derivedKeyHex; }

    /**
     * @brief Gets the BIP-39 word list (2048 words)
     * @return QStringList Reference to the static word list
     */
    static const QStringList &wordList();

    /**
     * @brief Connects this engine to a PostQuantumCrypto instance
     *
     * When a mnemonic is set, this allows automatic generation of PQ key pairs.
     * The connection enables seamless integration between mnemonic-based key
     * derivation and post-quantum cryptographic operations.
     *
     * @param pqCrypto Pointer to the PostQuantumCrypto instance
     */
    void setPostQuantumCrypto(PostQuantumCrypto *pqCrypto) { m_pqCrypto = pqCrypto; }

signals:
    /**
     * @brief Emitted when the mnemonic phrase changes
     */
    void mnemonicChanged();

    /**
     * @brief Emitted when a key is derived from the mnemonic
     */
    void keyDerived();

private:
    QString m_currentMnemonic;        ///< Currently stored mnemonic phrase
    QString m_derivedKeyHex;          ///< Derived key in hex format
    static QStringList s_wordList;    ///< Static BIP-39 word list (2048 words)
    static bool s_wordListLoaded;     ///< Flag indicating if word list is loaded
    PostQuantumCrypto *m_pqCrypto = nullptr;  ///< Connected PQ crypto instance
};
