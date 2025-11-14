#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QIcon>
#include <QQmlEngine>

#include "crypto/MnemonicEngine.h"
#include "crypto/PostQuantumCrypto.h"

// QML singleton provider functions
static QObject *mnemonicEngineProvider(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine)
    Q_UNUSED(scriptEngine)
    static MnemonicEngine *instance = nullptr;
    if (!instance) {
        instance = new MnemonicEngine();
    }
    return instance;
}

static QObject *postQuantumCryptoProvider(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine)
    Q_UNUSED(scriptEngine)
    static PostQuantumCrypto *instance = nullptr;
    if (!instance) {
        instance = new PostQuantumCrypto();
    }
    return instance;
}

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    app.setApplicationName("cybou");
    app.setOrganizationName("cybou");

    QQmlApplicationEngine engine;

    // Register QML singletons
    qmlRegisterSingletonType<MnemonicEngine>("CybouWallet", 1, 0, "MnemonicEngine", mnemonicEngineProvider);
    qmlRegisterSingletonType<PostQuantumCrypto>("CybouWallet", 1, 0, "PostQuantumCrypto", postQuantumCryptoProvider);

    // Get singleton instances and connect them
    MnemonicEngine *mnemonicEngine = qobject_cast<MnemonicEngine*>(mnemonicEngineProvider(nullptr, nullptr));
    PostQuantumCrypto *pqCrypto = qobject_cast<PostQuantumCrypto*>(postQuantumCryptoProvider(nullptr, nullptr));

    if (mnemonicEngine && pqCrypto) {
        mnemonicEngine->setPostQuantumCrypto(pqCrypto);
    }

    const QUrl url(QStringLiteral("qrc:/CybouWallet/qml/Main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
                     &app, [url](QObject *obj, const QUrl &objUrl) {
        if (!obj && url == objUrl)
            QCoreApplication::exit(-1);
    }, Qt::QueuedConnection);

    engine.load(url);

    const int result = app.exec();
    return result;
}
