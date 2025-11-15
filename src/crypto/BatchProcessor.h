/**
 * @file BatchProcessor.h
 * @brief Multi-threaded batch file processing for encryption/decryption operations
 *
 * Provides concurrent processing of multiple files with progress tracking,
 * pause/resume/cancel capabilities, and proper error handling.
 */

#ifndef BATCHPROCESSOR_H
#define BATCHPROCESSOR_H

#include <QObject>
#include <QThreadPool>
#include <QRunnable>
#include <QQueue>
#include <QMutex>
#include <QWaitCondition>
#include <QAtomicInt>
#include <QElapsedTimer>
#include <QHash>
#include <QSet>

#include "KeyManager.h"
#include "EncryptionEngine.h"

/**
 * @enum BatchOperation
 * @brief Types of batch operations supported
 */
enum class BatchOperation {
    Encrypt,
    Decrypt,
    None
};

/**
 * @enum BatchStatus
 * @brief Current status of batch processing
 */
enum class BatchStatus {
    Idle,
    Running,
    Paused,
    Cancelled,
    Completed,
    Error
};

/**
 * @struct BatchFileItem
 * @brief Represents a single file in the batch queue
 */
struct BatchFileItem {
    QString inputPath;
    QString outputPath;
    qint64 fileSize = 0;
    BatchOperation operation = BatchOperation::None;
    QString status = "Queued";
    QString errorMessage;
    int progress = 0;
    qint64 startTime = 0;
    qint64 endTime = 0;
    bool completed = false;
    bool success = false;

    BatchFileItem() = default;
    BatchFileItem(const QString& in, const QString& out, BatchOperation op)
        : inputPath(in), outputPath(out), operation(op) {}
};

/**
 * @class FileWorker
 * @brief QRunnable worker for processing individual files
 */
class FileWorker : public QObject, public QRunnable {
    Q_OBJECT

public:
    FileWorker(BatchFileItem* item, KeyManager* keyManager, int workerId, QObject* parent = nullptr);

    void run() override;

signals:
    void progressUpdated(int workerId, int progress, const QString& status);
    void completed(int workerId, bool success, const QString& errorMessage = QString());

private:
    BatchFileItem* m_item;
    KeyManager* m_keyManager;
    int m_workerId;
    QAtomicInt m_cancelled;
};

/**
 * @class BatchProcessor
 * @brief Manages multi-threaded batch file processing operations
 *
 * Features:
 * - Concurrent file processing using QThreadPool
 * - Real-time progress tracking for individual files and overall batch
 * - Pause/resume/cancel capabilities
 * - Proper error handling and recovery
 * - Memory-efficient processing for large file sets
 */
class BatchProcessor : public QObject {
    Q_OBJECT

public:
    explicit BatchProcessor(KeyManager* keyManager, QObject* parent = nullptr);
    ~BatchProcessor();

    // Batch management
    void addFile(const QString& inputPath, const QString& outputPath, BatchOperation operation);
    void addFiles(const QStringList& inputPaths, const QString& outputDir, BatchOperation operation);
    void clearQueue();

    // Control operations
    void startProcessing();
    void pauseProcessing();
    void resumeProcessing();
    void cancelProcessing();

    // Status queries
    BatchStatus status() const { return m_status; }
    int queueSize() const { return m_queue.size(); }
    int completedCount() const { return m_completedCount; }
    int successCount() const { return m_successCount; }
    int errorCount() const { return m_errorCount; }
    int activeWorkers() const { return m_activeWorkers.size(); }
    double overallProgress() const;
    QString currentStatusMessage() const;

    // Configuration
    void setMaxConcurrentWorkers(int maxWorkers);
    void setOutputDirectory(const QString& dir) { m_outputDirectory = dir; }

    // Data access for UI
    QVariantList fileList() const;

signals:
    // Overall batch progress
    void batchProgressUpdated(double progress, const QString& status);
    void batchCompleted(int totalFiles, int successCount, int errorCount, qint64 totalTimeMs);

    // Individual file progress
    void fileProgressUpdated(int fileIndex, int progress, const QString& status);
    void fileCompleted(int fileIndex, bool success, const QString& errorMessage);

    // Status changes
    void statusChanged(BatchStatus newStatus);
    void queueChanged();

private slots:
    void onWorkerProgress(int workerId, int progress, const QString& status);
    void onWorkerCompleted(int workerId, bool success, const QString& errorMessage);
    void processNextItems();

private:
    KeyManager* m_keyManager;
    QThreadPool* m_threadPool;
    QList<BatchFileItem> m_queue;
    QHash<int, int> m_activeWorkersMap; // workerId -> itemIndex
    mutable QMutex m_mutex;
    QWaitCondition m_waitCondition;
    QElapsedTimer m_batchTimer;

    BatchStatus m_status;
    int m_maxConcurrentWorkers;
    int m_completedCount;
    int m_successCount;
    int m_errorCount;
    QSet<int> m_activeWorkers; // Set of active worker IDs
    QString m_outputDirectory;
    int m_nextWorkerId;

    void updateStatus(BatchStatus newStatus);
    QString generateOutputPath(const QString& inputPath, BatchOperation operation) const;
    bool validateFile(const QString& filePath) const;
};

#endif // BATCHPROCESSOR_H