#include "MnemonicEngine.h"

#include <QCoreApplication>
#include <QDebug>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    MnemonicEngine engine;

    // Test mnemonic generation
    QString mnemonic = engine.generateMnemonic(12);
    qDebug() << "Generated mnemonic:" << mnemonic;

    // Test validation
    bool valid = engine.validateMnemonic(mnemonic);
    qDebug() << "Mnemonic valid:" << valid;

    // Test key derivation
    engine.setMnemonic(mnemonic);
    QString key = engine.derivedKey();
    qDebug() << "Derived key:" << key;

    return 0;
}