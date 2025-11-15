/****************************************************************************
** Meta object code from reading C++ file 'BatchProcessor.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.10.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../src/crypto/BatchProcessor.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'BatchProcessor.h' doesn't include <QObject>."
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
struct qt_meta_tag_ZN10FileWorkerE_t {};
} // unnamed namespace

template <> constexpr inline auto FileWorker::qt_create_metaobjectdata<qt_meta_tag_ZN10FileWorkerE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "FileWorker",
        "progressUpdated",
        "",
        "workerId",
        "progress",
        "status",
        "completed",
        "success",
        "errorMessage"
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'progressUpdated'
        QtMocHelpers::SignalData<void(int, int, const QString &)>(1, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Int, 3 }, { QMetaType::Int, 4 }, { QMetaType::QString, 5 },
        }}),
        // Signal 'completed'
        QtMocHelpers::SignalData<void(int, bool, const QString &)>(6, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Int, 3 }, { QMetaType::Bool, 7 }, { QMetaType::QString, 8 },
        }}),
        // Signal 'completed'
        QtMocHelpers::SignalData<void(int, bool)>(6, 2, QMC::AccessPublic | QMC::MethodCloned, QMetaType::Void, {{
            { QMetaType::Int, 3 }, { QMetaType::Bool, 7 },
        }}),
    };
    QtMocHelpers::UintData qt_properties {
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<FileWorker, qt_meta_tag_ZN10FileWorkerE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject FileWorker::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10FileWorkerE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10FileWorkerE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN10FileWorkerE_t>.metaTypes,
    nullptr
} };

void FileWorker::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<FileWorker *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->progressUpdated((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<int>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3]))); break;
        case 1: _t->completed((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<bool>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3]))); break;
        case 2: _t->completed((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<bool>>(_a[2]))); break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (FileWorker::*)(int , int , const QString & )>(_a, &FileWorker::progressUpdated, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (FileWorker::*)(int , bool , const QString & )>(_a, &FileWorker::completed, 1))
            return;
    }
}

const QMetaObject *FileWorker::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *FileWorker::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10FileWorkerE_t>.strings))
        return static_cast<void*>(this);
    if (!strcmp(_clname, "QRunnable"))
        return static_cast< QRunnable*>(this);
    return QObject::qt_metacast(_clname);
}

int FileWorker::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void FileWorker::progressUpdated(int _t1, int _t2, const QString & _t3)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 0, nullptr, _t1, _t2, _t3);
}

// SIGNAL 1
void FileWorker::completed(int _t1, bool _t2, const QString & _t3)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 1, nullptr, _t1, _t2, _t3);
}
namespace {
struct qt_meta_tag_ZN14BatchProcessorE_t {};
} // unnamed namespace

template <> constexpr inline auto BatchProcessor::qt_create_metaobjectdata<qt_meta_tag_ZN14BatchProcessorE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "BatchProcessor",
        "batchProgressUpdated",
        "",
        "progress",
        "status",
        "batchCompleted",
        "totalFiles",
        "successCount",
        "errorCount",
        "totalTimeMs",
        "fileProgressUpdated",
        "fileIndex",
        "fileCompleted",
        "success",
        "errorMessage",
        "statusChanged",
        "BatchStatus",
        "newStatus",
        "queueChanged",
        "onWorkerProgress",
        "workerId",
        "onWorkerCompleted",
        "processNextItems"
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'batchProgressUpdated'
        QtMocHelpers::SignalData<void(double, const QString &)>(1, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Double, 3 }, { QMetaType::QString, 4 },
        }}),
        // Signal 'batchCompleted'
        QtMocHelpers::SignalData<void(int, int, int, qint64)>(5, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Int, 6 }, { QMetaType::Int, 7 }, { QMetaType::Int, 8 }, { QMetaType::LongLong, 9 },
        }}),
        // Signal 'fileProgressUpdated'
        QtMocHelpers::SignalData<void(int, int, const QString &)>(10, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Int, 11 }, { QMetaType::Int, 3 }, { QMetaType::QString, 4 },
        }}),
        // Signal 'fileCompleted'
        QtMocHelpers::SignalData<void(int, bool, const QString &)>(12, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Int, 11 }, { QMetaType::Bool, 13 }, { QMetaType::QString, 14 },
        }}),
        // Signal 'statusChanged'
        QtMocHelpers::SignalData<void(BatchStatus)>(15, 2, QMC::AccessPublic, QMetaType::Void, {{
            { 0x80000000 | 16, 17 },
        }}),
        // Signal 'queueChanged'
        QtMocHelpers::SignalData<void()>(18, 2, QMC::AccessPublic, QMetaType::Void),
        // Slot 'onWorkerProgress'
        QtMocHelpers::SlotData<void(int, int, const QString &)>(19, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::Int, 20 }, { QMetaType::Int, 3 }, { QMetaType::QString, 4 },
        }}),
        // Slot 'onWorkerCompleted'
        QtMocHelpers::SlotData<void(int, bool, const QString &)>(21, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::Int, 20 }, { QMetaType::Bool, 13 }, { QMetaType::QString, 14 },
        }}),
        // Slot 'processNextItems'
        QtMocHelpers::SlotData<void()>(22, 2, QMC::AccessPrivate, QMetaType::Void),
    };
    QtMocHelpers::UintData qt_properties {
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<BatchProcessor, qt_meta_tag_ZN14BatchProcessorE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject BatchProcessor::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN14BatchProcessorE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN14BatchProcessorE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN14BatchProcessorE_t>.metaTypes,
    nullptr
} };

void BatchProcessor::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<BatchProcessor *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->batchProgressUpdated((*reinterpret_cast<std::add_pointer_t<double>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2]))); break;
        case 1: _t->batchCompleted((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<int>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast<std::add_pointer_t<qint64>>(_a[4]))); break;
        case 2: _t->fileProgressUpdated((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<int>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3]))); break;
        case 3: _t->fileCompleted((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<bool>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3]))); break;
        case 4: _t->statusChanged((*reinterpret_cast<std::add_pointer_t<BatchStatus>>(_a[1]))); break;
        case 5: _t->queueChanged(); break;
        case 6: _t->onWorkerProgress((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<int>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3]))); break;
        case 7: _t->onWorkerCompleted((*reinterpret_cast<std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<bool>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3]))); break;
        case 8: _t->processNextItems(); break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (BatchProcessor::*)(double , const QString & )>(_a, &BatchProcessor::batchProgressUpdated, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (BatchProcessor::*)(int , int , int , qint64 )>(_a, &BatchProcessor::batchCompleted, 1))
            return;
        if (QtMocHelpers::indexOfMethod<void (BatchProcessor::*)(int , int , const QString & )>(_a, &BatchProcessor::fileProgressUpdated, 2))
            return;
        if (QtMocHelpers::indexOfMethod<void (BatchProcessor::*)(int , bool , const QString & )>(_a, &BatchProcessor::fileCompleted, 3))
            return;
        if (QtMocHelpers::indexOfMethod<void (BatchProcessor::*)(BatchStatus )>(_a, &BatchProcessor::statusChanged, 4))
            return;
        if (QtMocHelpers::indexOfMethod<void (BatchProcessor::*)()>(_a, &BatchProcessor::queueChanged, 5))
            return;
    }
}

const QMetaObject *BatchProcessor::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *BatchProcessor::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN14BatchProcessorE_t>.strings))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int BatchProcessor::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 9)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 9;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 9)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 9;
    }
    return _id;
}

// SIGNAL 0
void BatchProcessor::batchProgressUpdated(double _t1, const QString & _t2)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 0, nullptr, _t1, _t2);
}

// SIGNAL 1
void BatchProcessor::batchCompleted(int _t1, int _t2, int _t3, qint64 _t4)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 1, nullptr, _t1, _t2, _t3, _t4);
}

// SIGNAL 2
void BatchProcessor::fileProgressUpdated(int _t1, int _t2, const QString & _t3)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 2, nullptr, _t1, _t2, _t3);
}

// SIGNAL 3
void BatchProcessor::fileCompleted(int _t1, bool _t2, const QString & _t3)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 3, nullptr, _t1, _t2, _t3);
}

// SIGNAL 4
void BatchProcessor::statusChanged(BatchStatus _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 4, nullptr, _t1);
}

// SIGNAL 5
void BatchProcessor::queueChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 5, nullptr);
}
QT_WARNING_POP
