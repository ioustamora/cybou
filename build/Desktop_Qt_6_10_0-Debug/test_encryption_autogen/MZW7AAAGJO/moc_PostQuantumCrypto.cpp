/****************************************************************************
** Meta object code from reading C++ file 'PostQuantumCrypto.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.10.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../src/crypto/PostQuantumCrypto.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'PostQuantumCrypto.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 69
#error "This file was generated using the moc from 6.10.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN17PostQuantumCryptoE_t {};
} // unnamed namespace

template <> constexpr inline auto PostQuantumCrypto::qt_create_metaobjectdata<qt_meta_tag_ZN17PostQuantumCryptoE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "PostQuantumCrypto",
        "keysChanged",
        "",
        "operationCompleted",
        "operation",
        "success",
        "result",
        "generateKeyPair",
        "importKeyPair",
        "privateKeyHex",
        "publicKeyHex",
        "exportPrivateKey",
        "exportPublicKey",
        "signMessage",
        "message",
        "verifySignature",
        "signature",
        "encapsulateKey",
        "QVariantMap",
        "recipientPublicKeyHex",
        "decapsulateKey",
        "encapsulatedKey",
        "encryptText",
        "plaintext",
        "decryptText",
        "ciphertext",
        "saveEncryptedTextToFile",
        "content",
        "filePath",
        "loadEncryptedTextFromFile",
        "encryptFile",
        "inputFilePath",
        "outputFilePath",
        "decryptFile",
        "encryptBinary",
        "decryptBinary",
        "generateSharedSecret",
        "otherPublicKeyHex",
        "hasKeys",
        "publicKey",
        "keyAlgorithm"
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'keysChanged'
        QtMocHelpers::SignalData<void()>(1, 2, QMC::AccessPublic, QMetaType::Void),
        // Signal 'operationCompleted'
        QtMocHelpers::SignalData<void(const QString &, bool, const QString &)>(3, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 4 }, { QMetaType::Bool, 5 }, { QMetaType::QString, 6 },
        }}),
        // Method 'generateKeyPair'
        QtMocHelpers::MethodData<bool()>(7, 2, QMC::AccessPublic, QMetaType::Bool),
        // Method 'importKeyPair'
        QtMocHelpers::MethodData<bool(const QString &, const QString &)>(8, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 9 }, { QMetaType::QString, 10 },
        }}),
        // Method 'exportPrivateKey'
        QtMocHelpers::MethodData<QString() const>(11, 2, QMC::AccessPublic, QMetaType::QString),
        // Method 'exportPublicKey'
        QtMocHelpers::MethodData<QString() const>(12, 2, QMC::AccessPublic, QMetaType::QString),
        // Method 'signMessage'
        QtMocHelpers::MethodData<QString(const QString &)>(13, 2, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::QString, 14 },
        }}),
        // Method 'verifySignature'
        QtMocHelpers::MethodData<bool(const QString &, const QString &, const QString &)>(15, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 14 }, { QMetaType::QString, 16 }, { QMetaType::QString, 10 },
        }}),
        // Method 'encapsulateKey'
        QtMocHelpers::MethodData<QVariantMap(const QString &)>(17, 2, QMC::AccessPublic, 0x80000000 | 18, {{
            { QMetaType::QString, 19 },
        }}),
        // Method 'decapsulateKey'
        QtMocHelpers::MethodData<QByteArray(const QVariantMap &)>(20, 2, QMC::AccessPublic, QMetaType::QByteArray, {{
            { 0x80000000 | 18, 21 },
        }}),
        // Method 'encryptText'
        QtMocHelpers::MethodData<QString(const QString &)>(22, 2, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::QString, 23 },
        }}),
        // Method 'decryptText'
        QtMocHelpers::MethodData<QString(const QString &)>(24, 2, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::QString, 25 },
        }}),
        // Method 'saveEncryptedTextToFile'
        QtMocHelpers::MethodData<bool(const QString &, const QString &)>(26, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 27 }, { QMetaType::QString, 28 },
        }}),
        // Method 'loadEncryptedTextFromFile'
        QtMocHelpers::MethodData<QString(const QString &)>(29, 2, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::QString, 28 },
        }}),
        // Method 'encryptFile'
        QtMocHelpers::MethodData<bool(const QString &, const QString &)>(30, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 31 }, { QMetaType::QString, 32 },
        }}),
        // Method 'decryptFile'
        QtMocHelpers::MethodData<bool(const QString &, const QString &)>(33, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 31 }, { QMetaType::QString, 32 },
        }}),
        // Method 'encryptBinary'
        QtMocHelpers::MethodData<QByteArray(const QByteArray &)>(34, 2, QMC::AccessPublic, QMetaType::QByteArray, {{
            { QMetaType::QByteArray, 23 },
        }}),
        // Method 'decryptBinary'
        QtMocHelpers::MethodData<QByteArray(const QByteArray &)>(35, 2, QMC::AccessPublic, QMetaType::QByteArray, {{
            { QMetaType::QByteArray, 25 },
        }}),
        // Method 'generateSharedSecret'
        QtMocHelpers::MethodData<QString(const QString &)>(36, 2, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::QString, 37 },
        }}),
    };
    QtMocHelpers::UintData qt_properties {
        // property 'hasKeys'
        QtMocHelpers::PropertyData<bool>(38, QMetaType::Bool, QMC::DefaultPropertyFlags, 0),
        // property 'publicKey'
        QtMocHelpers::PropertyData<QString>(39, QMetaType::QString, QMC::DefaultPropertyFlags, 0),
        // property 'keyAlgorithm'
        QtMocHelpers::PropertyData<QString>(40, QMetaType::QString, QMC::DefaultPropertyFlags | QMC::Constant),
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<PostQuantumCrypto, qt_meta_tag_ZN17PostQuantumCryptoE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject PostQuantumCrypto::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN17PostQuantumCryptoE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN17PostQuantumCryptoE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN17PostQuantumCryptoE_t>.metaTypes,
    nullptr
} };

void PostQuantumCrypto::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<PostQuantumCrypto *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->keysChanged(); break;
        case 1: _t->operationCompleted((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<bool>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3]))); break;
        case 2: { bool _r = _t->generateKeyPair();
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 3: { bool _r = _t->importKeyPair((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 4: { QString _r = _t->exportPrivateKey();
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 5: { QString _r = _t->exportPublicKey();
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 6: { QString _r = _t->signMessage((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 7: { bool _r = _t->verifySignature((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 8: { QVariantMap _r = _t->encapsulateKey((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QVariantMap*>(_a[0]) = std::move(_r); }  break;
        case 9: { QByteArray _r = _t->decapsulateKey((*reinterpret_cast<std::add_pointer_t<QVariantMap>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QByteArray*>(_a[0]) = std::move(_r); }  break;
        case 10: { QString _r = _t->encryptText((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 11: { QString _r = _t->decryptText((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 12: { bool _r = _t->saveEncryptedTextToFile((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 13: { QString _r = _t->loadEncryptedTextFromFile((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 14: { bool _r = _t->encryptFile((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 15: { bool _r = _t->decryptFile((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 16: { QByteArray _r = _t->encryptBinary((*reinterpret_cast<std::add_pointer_t<QByteArray>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QByteArray*>(_a[0]) = std::move(_r); }  break;
        case 17: { QByteArray _r = _t->decryptBinary((*reinterpret_cast<std::add_pointer_t<QByteArray>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QByteArray*>(_a[0]) = std::move(_r); }  break;
        case 18: { QString _r = _t->generateSharedSecret((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (PostQuantumCrypto::*)()>(_a, &PostQuantumCrypto::keysChanged, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (PostQuantumCrypto::*)(const QString & , bool , const QString & )>(_a, &PostQuantumCrypto::operationCompleted, 1))
            return;
    }
    if (_c == QMetaObject::ReadProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast<bool*>(_v) = _t->hasKeys(); break;
        case 1: *reinterpret_cast<QString*>(_v) = _t->publicKey(); break;
        case 2: *reinterpret_cast<QString*>(_v) = _t->keyAlgorithm(); break;
        default: break;
        }
    }
}

const QMetaObject *PostQuantumCrypto::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *PostQuantumCrypto::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN17PostQuantumCryptoE_t>.strings))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int PostQuantumCrypto::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 19)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 19;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 19)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 19;
    }
    if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::BindableProperty
            || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void PostQuantumCrypto::keysChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void PostQuantumCrypto::operationCompleted(const QString & _t1, bool _t2, const QString & _t3)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 1, nullptr, _t1, _t2, _t3);
}
QT_WARNING_POP
