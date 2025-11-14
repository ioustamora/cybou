/****************************************************************************
** Meta object code from reading C++ file 'MnemonicEngine.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.8.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../src/crypto/MnemonicEngine.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'MnemonicEngine.h' doesn't include <QObject>."
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
struct qt_meta_tag_ZN14MnemonicEngineE_t {};
} // unnamed namespace


#ifdef QT_MOC_HAS_STRINGDATA
static constexpr auto qt_meta_stringdata_ZN14MnemonicEngineE = QtMocHelpers::stringData(
    "MnemonicEngine",
    "mnemonicChanged",
    "",
    "keyDerived",
    "generateMnemonic",
    "words",
    "validateMnemonic",
    "mnemonic",
    "setMnemonic",
    "deriveKeyFromMnemonic",
    "passphrase",
    "hasMnemonic",
    "currentMnemonic",
    "derivedKey"
);
#else  // !QT_MOC_HAS_STRINGDATA
#error "qtmochelpers.h not found or too old."
#endif // !QT_MOC_HAS_STRINGDATA

Q_CONSTINIT static const uint qt_meta_data_ZN14MnemonicEngineE[] = {

 // content:
      12,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       3,   78, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   62,    2, 0x06,    4 /* Public */,
       3,    0,   63,    2, 0x06,    5 /* Public */,

 // methods: name, argc, parameters, tag, flags, initial metatype offsets
       4,    1,   64,    2, 0x02,    6 /* Public */,
       4,    0,   67,    2, 0x22,    8 /* Public | MethodCloned */,
       6,    1,   68,    2, 0x102,    9 /* Public | MethodIsConst  */,
       8,    1,   71,    2, 0x02,   11 /* Public */,
       9,    1,   74,    2, 0x02,   13 /* Public */,
       9,    0,   77,    2, 0x22,   15 /* Public | MethodCloned */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,

 // methods: parameters
    QMetaType::QString, QMetaType::Int,    5,
    QMetaType::QString,
    QMetaType::Bool, QMetaType::QString,    7,
    QMetaType::Bool, QMetaType::QString,    7,
    QMetaType::Void, QMetaType::QString,   10,
    QMetaType::Void,

 // properties: name, type, flags, notifyId, revision
      11, QMetaType::Bool, 0x00015001, uint(0), 0,
      12, QMetaType::QString, 0x00015001, uint(0), 0,
      13, QMetaType::QString, 0x00015001, uint(1), 0,

       0        // eod
};

Q_CONSTINIT const QMetaObject MnemonicEngine::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_ZN14MnemonicEngineE.offsetsAndSizes,
    qt_meta_data_ZN14MnemonicEngineE,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_tag_ZN14MnemonicEngineE_t,
        // property 'hasMnemonic'
        QtPrivate::TypeAndForceComplete<bool, std::true_type>,
        // property 'currentMnemonic'
        QtPrivate::TypeAndForceComplete<QString, std::true_type>,
        // property 'derivedKey'
        QtPrivate::TypeAndForceComplete<QString, std::true_type>,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<MnemonicEngine, std::true_type>,
        // method 'mnemonicChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'keyDerived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'generateMnemonic'
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'generateMnemonic'
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'validateMnemonic'
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'setMnemonic'
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'deriveKeyFromMnemonic'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'deriveKeyFromMnemonic'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void MnemonicEngine::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<MnemonicEngine *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->mnemonicChanged(); break;
        case 1: _t->keyDerived(); break;
        case 2: { QString _r = _t->generateMnemonic((*reinterpret_cast< std::add_pointer_t<int>>(_a[1])));
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        case 3: { QString _r = _t->generateMnemonic();
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        case 4: { bool _r = _t->validateMnemonic((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 5: { bool _r = _t->setMnemonic((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 6: _t->deriveKeyFromMnemonic((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 7: _t->deriveKeyFromMnemonic(); break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _q_method_type = void (MnemonicEngine::*)();
            if (_q_method_type _q_method = &MnemonicEngine::mnemonicChanged; *reinterpret_cast<_q_method_type *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _q_method_type = void (MnemonicEngine::*)();
            if (_q_method_type _q_method = &MnemonicEngine::keyDerived; *reinterpret_cast<_q_method_type *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
    }
    if (_c == QMetaObject::ReadProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast< bool*>(_v) = _t->hasMnemonic(); break;
        case 1: *reinterpret_cast< QString*>(_v) = _t->currentMnemonic(); break;
        case 2: *reinterpret_cast< QString*>(_v) = _t->derivedKey(); break;
        default: break;
        }
    }
}

const QMetaObject *MnemonicEngine::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MnemonicEngine::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ZN14MnemonicEngineE.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int MnemonicEngine::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 8)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 8;
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
void MnemonicEngine::mnemonicChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void MnemonicEngine::keyDerived()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}
QT_WARNING_POP
