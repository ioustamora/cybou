/**
 * @file BatchProcessor.cpp
 * @brief Implementation of multi-threaded batch file processing
 */

#include "BatchProcessor.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QCoreApplication>

/**
 * @file BatchProcessor.cpp
 * @brief Implementation of multi-threaded batch file processing
 */

#include "BatchProcessor.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QCoreApplication>
#include <QTimer>
#include <QDateTime>

/**
 * @brief FileWorker constructor
 */
FileWorker::FileWorker(BatchFileItem* item, KeyManager* keyManager, int workerId, QObject* parent)
    : QObject(parent), QRunnable(), m_item(item), m_keyManager(keyManager), m_workerId(workerId)
{
    setAutoDelete(false); // We'll manage deletion ourselves
    m_cancelled.store(0);
}

/**
 * @brief FileWorker run method - processes a single file
 */
void FileWorker::run() {
    if (!m_item || m_cancelled.load()) {
        emit completed(m_workerId, false, "Cancelled");
        return;
    }

    try {
        // Create temporary encryption engine for this worker
        EncryptionEngine engine(m_keyManager);

        // Update status
        m_item->startTime = QDateTime::currentMSecsSinceEpoch();
        m_item->status = "Processing...";

        emit progressUpdated(m_workerId, 10, "Initializing...");

        bool success = false;
        QString errorMessage;

        if (m_item->operation == BatchOperation::Encrypt) {
            // Generate output path if not specified
            if (m_item->outputPath.isEmpty()) {
                QFileInfo inputInfo(m_item->inputPath);
                QString outputName = inputInfo.baseName() + "_encrypted";
                if (!inputInfo.suffix().isEmpty()) {
                    outputName += "." + inputInfo.suffix();
                }
                m_item->outputPath = inputInfo.absoluteDir().absoluteFilePath(outputName);
            }

            emit progressUpdated(m_workerId, 25, "Encrypting file...");
            success = engine.encryptFile(m_item->inputPath, m_item->outputPath);
            if (!success) {
                errorMessage = "Encryption failed";
            }
        } else if (m_item->operation == BatchOperation::Decrypt) {
            // Generate output path if not specified
            if (m_item->outputPath.isEmpty()) {
                QFileInfo inputInfo(m_item->inputPath);
                QString baseName = inputInfo.baseName();
                // Remove "_encrypted" suffix if present
                if (baseName.endsWith("_encrypted")) {
                    baseName = baseName.left(baseName.length() - 10);
                }
                QString outputName = baseName + "_decrypted";
                if (!inputInfo.suffix().isEmpty()) {
                    outputName += "." + inputInfo.suffix();
                }
                m_item->outputPath = inputInfo.absoluteDir().absoluteFilePath(outputName);
            }

            emit progressUpdated(m_workerId, 25, "Decrypting file...");
            success = engine.decryptFile(m_item->inputPath, m_item->outputPath);
            if (!success) {
                errorMessage = "Decryption failed";
            }
        }

        emit progressUpdated(m_workerId, 90, "Finalizing...");

        m_item->endTime = QDateTime::currentMSecsSinceEpoch();
        m_item->completed = true;
        m_item->success = success;
        m_item->errorMessage = errorMessage;
        m_item->status = success ? "Completed" : "Failed: " + errorMessage;

        emit progressUpdated(m_workerId, 100, m_item->status);
        emit completed(m_workerId, success, errorMessage);

    } catch (const std::exception& e) {
        m_item->endTime = QDateTime::currentMSecsSinceEpoch();
        m_item->completed = true;
        m_item->success = false;
        m_item->errorMessage = QString("Exception: %1").arg(e.what());
        m_item->status = "Failed: " + m_item->errorMessage;

        emit progressUpdated(m_workerId, 100, m_item->status);
        emit completed(m_workerId, false, m_item->errorMessage);
    }
}

/**
 * @brief BatchProcessor constructor
 */
BatchProcessor::BatchProcessor(KeyManager* keyManager, QObject* parent)
    : QObject(parent)
    , m_keyManager(keyManager)
    , m_threadPool(new QThreadPool(this))
    , m_status(BatchStatus::Idle)
    , m_maxConcurrentWorkers(QThread::idealThreadCount())
    , m_completedCount(0)
    , m_successCount(0)
    , m_errorCount(0)
    , m_activeWorkers(0)
    , m_nextWorkerId(0)
{
    m_threadPool->setMaxThreadCount(m_maxConcurrentWorkers);
}

/**
 * @brief BatchProcessor destructor
 */
BatchProcessor::~BatchProcessor() {
    cancelProcessing();
    m_threadPool->waitForDone();
}

/**
 * @brief Add a single file to the processing queue
 */
void BatchProcessor::addFile(const QString& inputPath, const QString& outputPath, BatchOperation operation) {
    QMutexLocker locker(&m_mutex);

    if (!validateFile(inputPath)) {
        qWarning() << "BatchProcessor: Invalid input file:" << inputPath;
        return;
    }

    QFileInfo inputInfo(inputPath);
    BatchFileItem item(inputPath, outputPath, operation);
    item.fileSize = inputInfo.size();

    m_queue.append(item);
    emit queueChanged();
}

/**
 * @brief Add multiple files to the processing queue
 */
void BatchProcessor::addFiles(const QStringList& inputPaths, const QString& outputDir, BatchOperation operation) {
    QMutexLocker locker(&m_mutex);

    for (const QString& inputPath : inputPaths) {
        if (!validateFile(inputPath)) {
            qWarning() << "BatchProcessor: Invalid input file:" << inputPath;
            continue;
        }

        QString outputPath = generateOutputPath(inputPath, operation);
        if (!outputDir.isEmpty()) {
            QFileInfo inputInfo(inputPath);
            outputPath = QDir(outputDir).absoluteFilePath(QFileInfo(outputPath).fileName());
        }

        QFileInfo inputInfo(inputPath);
        BatchFileItem item(inputPath, outputPath, operation);
        item.fileSize = inputInfo.size();

        m_queue.append(item);
    }

    emit queueChanged();
}

/**
 * @brief Clear the processing queue
 */
void BatchProcessor::clearQueue() {
    QMutexLocker locker(&m_mutex);

    if (m_status == BatchStatus::Running) {
        cancelProcessing();
    }

    m_queue.clear();
    m_completedCount = 0;
    m_successCount = 0;
    m_errorCount = 0;

    emit queueChanged();
}

/**
 * @brief Start processing the batch queue
 */
void BatchProcessor::startProcessing() {
    QMutexLocker locker(&m_mutex);

    if (m_queue.isEmpty() || m_status == BatchStatus::Running) {
        return;
    }

    updateStatus(BatchStatus::Running);
    m_batchTimer.start();
    m_completedCount = 0;
    m_successCount = 0;
    m_errorCount = 0;

    // Start processing items
    processNextItems();
}

/**
 * @brief Pause batch processing
 */
void BatchProcessor::pauseProcessing() {
    if (m_status == BatchStatus::Running) {
        updateStatus(BatchStatus::Paused);
        // Workers will complete their current tasks but no new ones will start
    }
}

/**
 * @brief Resume batch processing
 */
void BatchProcessor::resumeProcessing() {
    if (m_status == BatchStatus::Paused) {
        updateStatus(BatchStatus::Running);
        processNextItems();
    }
}

/**
 * @brief Cancel batch processing
 */
void BatchProcessor::cancelProcessing() {
    updateStatus(BatchStatus::Cancelled);

    // Cancel active workers
    QMutexLocker locker(&m_mutex);
    for (auto it = m_activeWorkers.begin(); it != m_activeWorkers.end(); ++it) {
        // Note: In a real implementation, you'd need to add cancellation support to FileWorker
        // For now, we'll just wait for them to complete
    }
}

/**
 * @brief Set maximum number of concurrent workers
 */
void BatchProcessor::setMaxConcurrentWorkers(int maxWorkers) {
    m_maxConcurrentWorkers = qMax(1, maxWorkers);
    m_threadPool->setMaxThreadCount(m_maxConcurrentWorkers);
}

/**
 * @brief Get overall progress percentage
 */
double BatchProcessor::overallProgress() const {
    QMutexLocker locker(&m_mutex);

    if (m_queue.isEmpty()) {
        return 0.0;
    }

    int totalItems = m_queue.size();
    return (static_cast<double>(m_completedCount) / totalItems) * 100.0;
}

/**
 * @brief Get current status message
 */
QString BatchProcessor::currentStatusMessage() const {
    QMutexLocker locker(&m_mutex);

    switch (m_status) {
        case BatchStatus::Idle:
            return QString("Ready - %1 files queued").arg(m_queue.size());
        case BatchStatus::Running:
            return QString("Processing %1/%2 files (%3 active workers)")
                    .arg(m_completedCount).arg(m_queue.size()).arg(m_activeWorkers);
        case BatchStatus::Paused:
            return QString("Paused - %1/%2 files completed").arg(m_completedCount).arg(m_queue.size());
        case BatchStatus::Cancelled:
            return "Cancelled";
        case BatchStatus::Completed:
            return QString("Completed - %1 successful, %2 failed").arg(m_successCount).arg(m_errorCount);
        case BatchStatus::Error:
            return "Error occurred";
        default:
            return "Unknown status";
    }
}

/**
 * @brief Process next items in the queue
 */
void BatchProcessor::processNextItems() {
    QMutexLocker locker(&m_mutex);

    if (m_status != BatchStatus::Running) {
        return;
    }

    // Start new workers up to the limit
    while (m_activeWorkers < m_maxConcurrentWorkers && !m_queue.isEmpty()) {
        // Find next unprocessed item
        int itemIndex = -1;
        for (int i = 0; i < m_queue.size(); ++i) {
            if (!m_queue[i].completed) {
                itemIndex = i;
                break;
            }
        }

        if (itemIndex == -1) {
            break; // No more items to process
        }

        // Create worker for this item
        FileWorker* worker = new FileWorker(&m_queue[itemIndex], m_keyManager, m_nextWorkerId++);
        m_activeWorkers++;

        // Connect worker signals
        connect(worker, &FileWorker::progressUpdated,
                this, &BatchProcessor::onWorkerProgress, Qt::QueuedConnection);
        connect(worker, &FileWorker::completed,
                this, &BatchProcessor::onWorkerCompleted, Qt::QueuedConnection);

        // Track active worker
        m_activeWorkersMap[m_nextWorkerId - 1] = itemIndex;

        // Start the worker
        m_threadPool->start(worker);
    }

    // Update overall progress
    double progress = overallProgress();
    emit batchProgressUpdated(progress, currentStatusMessage());
}

/**
 * @brief Handle worker progress updates
 */
void BatchProcessor::onWorkerProgress(int workerId, int progress, const QString& status) {
    QMutexLocker locker(&m_mutex);

    if (m_activeWorkersMap.contains(workerId)) {
        int itemIndex = m_activeWorkersMap[workerId];
        if (itemIndex >= 0 && itemIndex < m_queue.size()) {
            m_queue[itemIndex].progress = progress;
            m_queue[itemIndex].status = status;

            emit fileProgressUpdated(itemIndex, progress, status);
        }
    }
}

/**
 * @brief Handle worker completion
 */
void BatchProcessor::onWorkerCompleted(int workerId, bool success, const QString& errorMessage) {
    QMutexLocker locker(&m_mutex);

    if (m_activeWorkersMap.contains(workerId)) {
        int itemIndex = m_activeWorkersMap[workerId];
        if (itemIndex >= 0 && itemIndex < m_queue.size()) {
            BatchFileItem& item = m_queue[itemIndex];
            item.completed = true;
            item.success = success;
            item.errorMessage = errorMessage;

            m_completedCount++;
            if (success) {
                m_successCount++;
            } else {
                m_errorCount++;
            }

            emit fileCompleted(itemIndex, success, errorMessage);
        }

        m_activeWorkers--;
        m_activeWorkersMap.remove(workerId);

        // Check if batch is complete
        if (m_completedCount == m_queue.size()) {
            qint64 totalTime = m_batchTimer.elapsed();
            updateStatus(BatchStatus::Completed);
            emit batchCompleted(m_queue.size(), m_successCount, m_errorCount, totalTime);
        } else if (m_status == BatchStatus::Running) {
            // Start next items
            QTimer::singleShot(0, this, &BatchProcessor::processNextItems);
        }
    }
}

/**
 * @brief Update batch status
 */
void BatchProcessor::updateStatus(BatchStatus newStatus) {
    if (m_status != newStatus) {
        m_status = newStatus;
        emit statusChanged(newStatus);
    }
}

/**
 * @brief Generate output path for a file operation
 */
QString BatchProcessor::generateOutputPath(const QString& inputPath, BatchOperation operation) const {
    QFileInfo inputInfo(inputPath);
    QString baseName = inputInfo.baseName();
    QString suffix = inputInfo.suffix();

    QString outputName;
    if (operation == BatchOperation::Encrypt) {
        outputName = baseName + "_encrypted";
        if (!suffix.isEmpty()) {
            outputName += "." + suffix;
        }
    } else if (operation == BatchOperation::Decrypt) {
        if (baseName.endsWith("_encrypted")) {
            baseName = baseName.left(baseName.length() - 10);
        }
        outputName = baseName + "_decrypted";
        if (!suffix.isEmpty()) {
            outputName += "." + suffix;
        }
    }

    return inputInfo.absoluteDir().absoluteFilePath(outputName);
}

/**
 * @brief Validate input file
 */
bool BatchProcessor::validateFile(const QString& filePath) const {
    QFileInfo info(filePath);
    return info.exists() && info.isFile() && info.isReadable();
}