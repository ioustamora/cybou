/**
 * @file BatchProgressDialog.qml
 * @brief Dialog for displaying batch file processing progress
 *
 * Shows real-time progress for multi-threaded batch operations,
 * including individual file status, overall progress, and controls
 * for pause/resume/cancel operations.
 */

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs
import CybouWallet 1.0

/**
 * @component BatchProgressDialog
 * @brief Modal dialog showing batch processing progress
 *
 * Features:
 * - Overall batch progress bar
 * - Individual file progress list
 * - Pause/Resume/Cancel controls
 * - Real-time status updates
 * - Performance statistics
 */
Dialog {
    id: batchDialog
    title: qsTr("🔄 Batch Processing")
    modal: true
    standardButtons: Dialog.Close
    width: 700
    height: 500

    // Properties
    property bool darkMode: false
    property int totalFiles: 0
    property int completedFiles: 0
    property int successCount: 0
    property int errorCount: 0
    property double overallProgress: 0.0
    property string statusMessage: ""
    property var fileList: []

    // Internal properties
    property bool isRunning: false
    property bool isPaused: false
    property int activeWorkers: 0

    // Background styling
    background: Rectangle {
        color: batchDialog.darkMode ? "#2d2d2d" : "#ffffff"
        border.color: batchDialog.darkMode ? "#555555" : "#cccccc"
        border.width: 1
        radius: 8
    }

    // Content area
    ColumnLayout {
        anchors.fill: parent
        spacing: 15

        // Header with stats
        Rectangle {
            Layout.fillWidth: true
            height: 60
            color: batchDialog.darkMode ? "#1e1e1e" : "#f5f5f5"
            border.color: batchDialog.darkMode ? "#404040" : "#e0e0e0"
            border.width: 1
            radius: 4

            RowLayout {
                anchors.fill: parent
                anchors.margins: 10
                spacing: 15

                // Status icon and message
                Column {
                    Layout.fillWidth: true
                    spacing: 2

                    Label {
                        text: batchDialog.statusMessage
                        font.pixelSize: 14
                        font.bold: true
                        color: batchDialog.darkMode ? "#ffffff" : "#000000"
                    }

                    Label {
                        text: qsTr("%1 / %2 files • %3 successful • %4 failed")
                              .arg(batchDialog.completedFiles)
                              .arg(batchDialog.totalFiles)
                              .arg(batchDialog.successCount)
                              .arg(batchDialog.errorCount)
                        font.pixelSize: 11
                        color: batchDialog.darkMode ? "#b0b0b0" : "#666666"
                    }
                }

                // Control buttons
                Row {
                    spacing: 8
                    visible: batchDialog.isRunning

                    Button {
                        text: batchDialog.isPaused ? "▶️ Resume" : "⏸️ Pause"
                        onClicked: {
                            if (batchDialog.isPaused) {
                                PostQuantumCrypto.resumeBatchProcessing()
                            } else {
                                PostQuantumCrypto.pauseBatchProcessing()
                            }
                        }
                        font.pixelSize: 11
                    }

                    Button {
                        text: "⏹️ Cancel"
                        onClicked: PostQuantumCrypto.cancelBatchProcessing()
                        font.pixelSize: 11
                    }
                }
            }
        }

        // Overall progress bar
        Column {
            Layout.fillWidth: true
            spacing: 8

            Label {
                text: qsTr("Overall Progress:")
                font.bold: true
                font.pixelSize: 12
            }

            ProgressBar {
                id: overallProgressBar
                width: parent.width
                from: 0
                to: 100
                value: batchDialog.overallProgress

                background: Rectangle {
                    color: batchDialog.darkMode ? "#404040" : "#e9ecef"
                    border.color: batchDialog.darkMode ? "#606060" : "#dee2e6"
                    border.width: 1
                    radius: 4
                }

                contentItem: Item {
                    Rectangle {
                        width: overallProgressBar.visualPosition * parent.width
                        height: parent.height
                        color: batchDialog.errorCount > 0 ? "#dc3545" :
                               batchDialog.overallProgress >= 100 ? "#28a745" : "#007bff"
                        radius: 4
                    }
                }
            }

            Label {
                text: qsTr("%1% complete").arg(batchDialog.overallProgress.toFixed(1))
                font.pixelSize: 11
                color: batchDialog.darkMode ? "#b0b0b0" : "#666666"
                anchors.right: parent.right
            }
        }

        // File list header
        Label {
            text: qsTr("File Processing Status:")
            font.bold: true
            font.pixelSize: 12
        }

        // Scrollable file list
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            ListView {
                id: fileListView
                model: batchDialog.fileList
                spacing: 2

                delegate: Rectangle {
                    width: fileListView.width
                    height: 35
                    color: index % 2 === 0 ?
                           (batchDialog.darkMode ? "#2a2a2a" : "#f8f9fa") :
                           (batchDialog.darkMode ? "#252525" : "#ffffff")
                    border.color: batchDialog.darkMode ? "#404040" : "#e0e0e0"
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 10

                        // Status icon
                        Label {
                            text: {
                                if (modelData.status === "Completed") return "✅";
                                if (modelData.status.startsWith("Failed")) return "❌";
                                if (modelData.status === "Processing...") return "🔄";
                                return "⏳";
                            }
                            font.pixelSize: 12
                            Layout.preferredWidth: 20
                        }

                        // File name
                        Label {
                            text: {
                                var fileName = modelData.inputPath.split('/').pop() ||
                                               modelData.inputPath.split('\\').pop();
                                return fileName.length > 30 ?
                                       fileName.substring(0, 27) + "..." : fileName;
                            }
                            font.pixelSize: 11
                            Layout.fillWidth: true
                            elide: Text.ElideMiddle
                            color: batchDialog.darkMode ? "#ffffff" : "#000000"
                        }

                        // Individual progress bar
                        ProgressBar {
                            Layout.preferredWidth: 80
                            from: 0
                            to: 100
                            value: modelData.progress
                            visible: modelData.status !== "Queued" && modelData.status !== "Completed"

                            background: Rectangle {
                                color: batchDialog.darkMode ? "#404040" : "#e9ecef"
                                radius: 2
                            }

                            contentItem: Item {
                                Rectangle {
                                    width: parent.visualPosition * parent.width
                                    height: parent.height
                                    color: modelData.status.startsWith("Failed") ? "#dc3545" : "#007bff"
                                    radius: 2
                                }
                            }
                        }

                        // Status text
                        Label {
                            text: modelData.status
                            font.pixelSize: 10
                            Layout.preferredWidth: 80
                            color: {
                                if (modelData.status === "Completed") return batchDialog.darkMode ? "#81c784" : "#28a745";
                                if (modelData.status.startsWith("Failed")) return batchDialog.darkMode ? "#ef5350" : "#dc3545";
                                if (modelData.status === "Processing...") return batchDialog.darkMode ? "#90caf9" : "#007bff";
                                return batchDialog.darkMode ? "#b0b0b0" : "#666666";
                            }
                        }
                    }
                }
            }
        }

        // Footer with performance stats
        Rectangle {
            Layout.fillWidth: true
            height: 40
            color: batchDialog.darkMode ? "#1e1e1e" : "#f5f5f5"
            border.color: batchDialog.darkMode ? "#404040" : "#e0e0e0"
            border.width: 1
            radius: 4

            RowLayout {
                anchors.fill: parent
                anchors.margins: 8

                Label {
                    text: qsTr("Active workers: %1").arg(batchDialog.activeWorkers)
                    font.pixelSize: 11
                    color: batchDialog.darkMode ? "#b0b0b0" : "#666666"
                }

                Label {
                    text: batchDialog.isRunning ?
                          (batchDialog.isPaused ? "⏸️ Paused" : "▶️ Running") :
                          (batchDialog.overallProgress >= 100 ? "✅ Completed" : "⏹️ Stopped")
                    font.pixelSize: 11
                    font.bold: true
                    color: {
                        if (batchDialog.isPaused) return batchDialog.darkMode ? "#ffb74d" : "#ff9800";
                        if (batchDialog.isRunning) return batchDialog.darkMode ? "#81c784" : "#4caf50";
                        if (batchDialog.overallProgress >= 100) return batchDialog.darkMode ? "#81c784" : "#28a745";
                        return batchDialog.darkMode ? "#b0b0b0" : "#666666";
                    }
                    Layout.alignment: Qt.AlignRight
                }
            }
        }
    }

    // Connections to PostQuantumCrypto signals
    Connections {
        target: PostQuantumCrypto

        function onBatchProgressUpdated(progress, status) {
            batchDialog.overallProgress = progress;
            batchDialog.statusMessage = status;
        }

        function onFileProgressUpdated(fileIndex, progress, status) {
            if (fileIndex >= 0 && fileIndex < batchDialog.fileList.length) {
                batchDialog.fileList[fileIndex].progress = progress;
                batchDialog.fileList[fileIndex].status = status;
                fileListView.model = batchDialog.fileList; // Trigger update
            }
        }

        function onFileCompleted(fileIndex, success, errorMessage) {
            if (fileIndex >= 0 && fileIndex < batchDialog.fileList.length) {
                batchDialog.fileList[fileIndex].success = success;
                batchDialog.fileList[fileIndex].errorMessage = errorMessage;
                batchDialog.fileList[fileIndex].completed = true;
                fileListView.model = batchDialog.fileList; // Trigger update
            }
        }

        function onBatchCompleted(totalFiles, successCount, errorCount, totalTimeMs) {
            batchDialog.totalFiles = totalFiles;
            batchDialog.successCount = successCount;
            batchDialog.errorCount = errorCount;
            batchDialog.completedFiles = totalFiles;
            batchDialog.isRunning = false;

            var timeStr = totalTimeMs < 1000 ?
                          qsTr("%1 ms").arg(totalTimeMs) :
                          qsTr("%1 s").arg((totalTimeMs / 1000.0).toFixed(1));

            batchDialog.statusMessage = qsTr("Completed in %1").arg(timeStr);
        }

        function onBatchQueueChanged() {
            // Update file list when queue changes
            updateFileList();
        }
    }

    // Update file list from PostQuantumCrypto
    function updateFileList() {
        batchDialog.fileList = PostQuantumCrypto.batchFileList();
        batchDialog.totalFiles = PostQuantumCrypto.batchQueueSize();
        batchDialog.completedFiles = PostQuantumCrypto.batchCompletedCount();
        batchDialog.successCount = PostQuantumCrypto.batchSuccessCount();
        batchDialog.errorCount = PostQuantumCrypto.batchErrorCount();
        batchDialog.overallProgress = PostQuantumCrypto.batchOverallProgress();
        batchDialog.statusMessage = PostQuantumCrypto.batchStatusMessage();
    }

    // Initialize when opened
    onOpened: {
        updateFileList();
        batchDialog.isRunning = true;
        batchDialog.isPaused = false;
    }

    // Clean up when closed
    onClosed: {
        if (batchDialog.isRunning) {
            PostQuantumCrypto.cancelBatchProcessing();
        }
    }
}