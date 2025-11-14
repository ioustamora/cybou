#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QByteArray>

// Forward declaration
class PostQuantumCrypto;

// MnemonicEngine implements BIP-39 compatible mnemonic generation and validation,
// plus basic key derivation for demonstration purposes.
// Future work: integrate post-quantum cryptography (Kyber-like KEM + AEAD and ML-DSA/SLH-DSA-like signatures).

class MnemonicEngine : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool hasMnemonic READ hasMnemonic NOTIFY mnemonicChanged)
    Q_PROPERTY(QString currentMnemonic READ currentMnemonic NOTIFY mnemonicChanged)
    Q_PROPERTY(QString derivedKey READ derivedKey NOTIFY keyDerived)

public:
    explicit MnemonicEngine(QObject *parent = nullptr);

    Q_INVOKABLE QString generateMnemonic(int words = 12);
    Q_INVOKABLE bool validateMnemonic(const QString &mnemonic) const;
    Q_INVOKABLE bool setMnemonic(const QString &mnemonic); // Set and validate mnemonic
    Q_INVOKABLE void deriveKeyFromMnemonic(const QString &passphrase = QString());

    bool hasMnemonic() const { return !m_currentMnemonic.isEmpty(); }
    QString currentMnemonic() const { return m_currentMnemonic; }
    QString derivedKey() const { return m_derivedKeyHex; }

    // BIP-39 word list (2048 words)
    static const QStringList &wordList();

    // Integration with PQ crypto
    void setPostQuantumCrypto(PostQuantumCrypto *pqCrypto) { m_pqCrypto = pqCrypto; }

signals:
    void mnemonicChanged();
    void keyDerived();

private:
    QString m_currentMnemonic;
    QString m_derivedKeyHex;
    static QStringList s_wordList;
    static bool s_wordListLoaded;
    PostQuantumCrypto *m_pqCrypto = nullptr;
};
