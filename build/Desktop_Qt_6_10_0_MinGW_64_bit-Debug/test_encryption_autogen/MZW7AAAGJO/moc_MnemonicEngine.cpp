/****************************************************************************
** Meta object code from reading C++ file 'MnemonicEngine.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.10.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../src/crypto/MnemonicEngine.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'MnemonicEngine.h' doesn't include <QObject>."
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
struct qt_meta_tag_ZN14MnemonicEngineE_t {};
} // unnamed namespace

template <> constexpr inline auto MnemonicEngine::qt_create_metaobjectdata<qt_meta_tag_ZN14MnemonicEngineE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
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
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'mnemonicChanged'
        QtMocHelpers::SignalData<void()>(1, 2, QMC::AccessPublic, QMetaType::Void),
        // Signal 'keyDerived'
        QtMocHelpers::SignalData<void()>(3, 2, QMC::AccessPublic, QMetaType::Void),
        // Method 'generateMnemonic'
        QtMocHelpers::MethodData<QString(int)>(4, 2, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::Int, 5 },
        }}),
        // Method 'generateMnemonic'
        QtMocHelpers::MethodData<QString()>(4, 2, QMC::AccessPublic | QMC::MethodCloned, QMetaType::QString),
        // Method 'validateMnemonic'
        QtMocHelpers::MethodData<bool(const QString &) const>(6, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 7 },
        }}),
        // Method 'setMnemonic'
        QtMocHelpers::MethodData<bool(const QString &)>(8, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 7 },
        }}),
        // Method 'deriveKeyFromMnemonic'
        QtMocHelpers::MethodData<void(const QString &)>(9, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 10 },
        }}),
        // Method 'deriveKeyFromMnemonic'
        QtMocHelpers::MethodData<void()>(9, 2, QMC::AccessPublic | QMC::MethodCloned, QMetaType::Void),
    };
    QtMocHelpers::UintData qt_properties {
        // property 'hasMnemonic'
        QtMocHelpers::PropertyData<bool>(11, QMetaType::Bool, QMC::DefaultPropertyFlags, 0),
        // property 'currentMnemonic'
        QtMocHelpers::PropertyData<QString>(12, QMetaType::QString, QMC::DefaultPropertyFlags, 0),
        // property 'derivedKey'
        QtMocHelpers::PropertyData<QString>(13, QMetaType::QString, QMC::DefaultPropertyFlags, 1),
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<MnemonicEngine, qt_meta_tag_ZN14MnemonicEngineE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject MnemonicEngine::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN14MnemonicEngineE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN14MnemonicEngineE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN14MnemonicEngineE_t>.metaTypes,
    nullptr
} };

void MnemonicEngine::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<MnemonicEngine *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->mnemonicChanged(); break;
        case 1: _t->keyDerived(); break;
        case 2: { QString _r = _t->generateMnemonic((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 3: { QString _r = _t->generateMnemonic();
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 4: { bool _r = _t->validateMnemonic((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 5: { bool _r = _t->setMnemonic((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 6: _t->deriveKeyFromMnemonic((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 7: _t->deriveKeyFromMnemonic(); break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (MnemonicEngine::*)()>(_a, &MnemonicEngine::mnemonicChanged, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (MnemonicEngine::*)()>(_a, &MnemonicEngine::keyDerived, 1))
            return;
    }
    if (_c == QMetaObject::ReadProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast<bool*>(_v) = _t->hasMnemonic(); break;
        case 1: *reinterpret_cast<QString*>(_v) = _t->currentMnemonic(); break;
        case 2: *reinterpret_cast<QString*>(_v) = _t->derivedKey(); break;
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
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN14MnemonicEngineE_t>.strings))
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
