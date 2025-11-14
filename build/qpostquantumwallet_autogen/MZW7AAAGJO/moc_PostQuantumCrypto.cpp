/****************************************************************************
** Meta object code from reading C++ file 'PostQuantumCrypto.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.8.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../src/crypto/PostQuantumCrypto.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'PostQuantumCrypto.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.8.2. It"
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


#ifdef QT_MOC_HAS_STRINGDATA
static constexpr auto qt_meta_stringdata_ZN17PostQuantumCryptoE = QtMocHelpers::stringData(
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
    "generateSharedSecret",
    "otherPublicKeyHex",
    "hasKeys",
    "publicKey",
    "keyAlgorithm"
);
#else  // !QT_MOC_HAS_STRINGDATA
#error "qtmochelpers.h not found or too old."
#endif // !QT_MOC_HAS_STRINGDATA

Q_CONSTINIT static const uint qt_meta_data_ZN17PostQuantumCryptoE[] = {

 // content:
      12,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       3,  115, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   80,    2, 0x06,    4 /* Public */,
       3,    3,   81,    2, 0x06,    5 /* Public */,

 // methods: name, argc, parameters, tag, flags, initial metatype offsets
       7,    0,   88,    2, 0x02,    9 /* Public */,
       8,    2,   89,    2, 0x02,   10 /* Public */,
      11,    0,   94,    2, 0x102,   13 /* Public | MethodIsConst  */,
      12,    0,   95,    2, 0x102,   14 /* Public | MethodIsConst  */,
      13,    1,   96,    2, 0x02,   15 /* Public */,
      15,    3,   99,    2, 0x02,   17 /* Public */,
      17,    1,  106,    2, 0x02,   21 /* Public */,
      20,    1,  109,    2, 0x02,   23 /* Public */,
      22,    1,  112,    2, 0x02,   25 /* Public */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::Bool, QMetaType::QString,    4,    5,    6,

 // methods: parameters
    QMetaType::Bool,
    QMetaType::Bool, QMetaType::QString, QMetaType::QString,    9,   10,
    QMetaType::QString,
    QMetaType::QString,
    QMetaType::QString, QMetaType::QString,   14,
    QMetaType::Bool, QMetaType::QString, QMetaType::QString, QMetaType::QString,   14,   16,   10,
    0x80000000 | 18, QMetaType::QString,   19,
    QMetaType::QByteArray, 0x80000000 | 18,   21,
    QMetaType::QString, QMetaType::QString,   23,

 // properties: name, type, flags, notifyId, revision
      24, QMetaType::Bool, 0x00015001, uint(0), 0,
      25, QMetaType::QString, 0x00015001, uint(0), 0,
      26, QMetaType::QString, 0x00015401, uint(-1), 0,

       0        // eod
};

Q_CONSTINIT const QMetaObject PostQuantumCrypto::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_ZN17PostQuantumCryptoE.offsetsAndSizes,
    qt_meta_data_ZN17PostQuantumCryptoE,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_tag_ZN17PostQuantumCryptoE_t,
        // property 'hasKeys'
        QtPrivate::TypeAndForceComplete<bool, std::true_type>,
        // property 'publicKey'
        QtPrivate::TypeAndForceComplete<QString, std::true_type>,
        // property 'keyAlgorithm'
        QtPrivate::TypeAndForceComplete<QString, std::true_type>,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<PostQuantumCrypto, std::true_type>,
        // method 'keysChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'operationCompleted'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'generateKeyPair'
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        // method 'importKeyPair'
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'exportPrivateKey'
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'exportPublicKey'
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'signMessage'
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'verifySignature'
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'encapsulateKey'
        QtPrivate::TypeAndForceComplete<QVariantMap, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'decapsulateKey'
        QtPrivate::TypeAndForceComplete<QByteArray, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QVariantMap &, std::false_type>,
        // method 'generateSharedSecret'
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>
    >,
    nullptr
} };

void PostQuantumCrypto::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<PostQuantumCrypto *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->keysChanged(); break;
        case 1: _t->operationCompleted((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<bool>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        case 2: { bool _r = _t->generateKeyPair();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 3: { bool _r = _t->importKeyPair((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 4: { QString _r = _t->exportPrivateKey();
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        case 5: { QString _r = _t->exportPublicKey();
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        case 6: { QString _r = _t->signMessage((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        case 7: { bool _r = _t->verifySignature((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 8: { QVariantMap _r = _t->encapsulateKey((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast< QVariantMap*>(_a[0]) = std::move(_r); }  break;
        case 9: { QByteArray _r = _t->decapsulateKey((*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[1])));
            if (_a[0]) *reinterpret_cast< QByteArray*>(_a[0]) = std::move(_r); }  break;
        case 10: { QString _r = _t->generateSharedSecret((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _q_method_type = void (PostQuantumCrypto::*)();
            if (_q_method_type _q_method = &PostQuantumCrypto::keysChanged; *reinterpret_cast<_q_method_type *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _q_method_type = void (PostQuantumCrypto::*)(const QString & , bool , const QString & );
            if (_q_method_type _q_method = &PostQuantumCrypto::operationCompleted; *reinterpret_cast<_q_method_type *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
    }
    if (_c == QMetaObject::ReadProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast< bool*>(_v) = _t->hasKeys(); break;
        case 1: *reinterpret_cast< QString*>(_v) = _t->publicKey(); break;
        case 2: *reinterpret_cast< QString*>(_v) = _t->keyAlgorithm(); break;
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
    if (!strcmp(_clname, qt_meta_stringdata_ZN17PostQuantumCryptoE.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int PostQuantumCrypto::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 11)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 11;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 11)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 11;
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
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
