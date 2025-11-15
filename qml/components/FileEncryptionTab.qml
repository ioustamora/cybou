/**
 * @file FileEncryptionTab.qml
 * @brief File encryption/decryption interface component
 *
 * Provides UI for:
 * - Drag and drop file selection
 * - Single and batch file operations
 * - Progress tracking
 * - Keyboard shortcuts
 */

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Dialogs
import CybouWallet 1.0
import "./BatchProgressDialog.qml" as BatchDialog

/**
 * @component FileEncryptionTab
 * @brief Tab for encrypting and decrypting files
 *
 * Features:
 * - Drag-and-drop file selection
 * - Single file encrypt/decrypt
 * - Batch file processing
 * - Real-time progress indicators
 * - Keyboard shortcuts (Ctrl+E/D/B)
 */
Column {
    id: root
    spacing: 20
    width: parent.width * 0.85
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.topMargin: 30
    anchors.top: parent.top
    anchors.leftMargin: 20
    anchors.rightMargin: 20

    // Properties
    property bool darkMode: false
    property var selectedFiles: []
    property alias fileProgressVisible: fileProgressBar.visible
    property alias filePath: filePathField.text

    // Signals
    signal browseRequested()
    signal batchSelectRequested()
    signal filesDropped(var fileUrls)

    // Title Section
    Label {
        text: qsTr("📁 File/Folder Encryption")
        font.pixelSize: 20
        font.bold: true
        horizontalAlignment: Text.AlignHCenter
        width: parent.width
    }

    Label {
        text: qsTr("🗂️ 'Encrypt your files like a boss - quantum computers will cry trying to break this!'")
        font.pixelSize: 12
        horizontalAlignment: Text.AlignHCenter
        width: parent.width
        color: "#666666"
        font.italic: true
    }

    // Drag and Drop Area
    Rectangle {
        width: parent.width
        height: 140
        color: dragArea.containsDrag ? (root.darkMode ? "#2c3e50" : "#e3f2fd") : (root.darkMode ? "#1e1e1e" : "#f5f5f5")
        border.color: root.darkMode ? "#546e7a" : "#90caf9"
        border.width: 2
        radius: 8

        DropArea {
            id: dragArea
            anchors.fill: parent
            onDropped: function(drop) {
                if (drop.hasUrls) {
                    root.filesDropped(drop.urls)
                }
            }

            Column {
                anchors.centerIn: parent
                spacing: 8

                Label {
                    text: "🎯 Drag & Drop Files Here"
                    font.pixelSize: 16
                    font.bold: true
                    anchors.horizontalCenter: parent.horizontalCenter
                    color: root.darkMode ? "#ffffff" : "#000000"
                }

                Label {
                    text: "or use the browse button below"
                    font.pixelSize: 12
                    anchors.horizontalCenter: parent.horizontalCenter
                    color: root.darkMode ? "#b0b0b0" : "#666666"
                }

                Label {
                    text: "💡 Multiple files = batch mode"
                    font.pixelSize: 11
                    font.italic: true
                    anchors.horizontalCenter: parent.horizontalCenter
                    color: root.darkMode ? "#90caf9" : "#2196f3"
                }
            }
        }
    }

    // File Path Input Row
    Row {
        spacing: 12
        width: parent.width
        topPadding: 10

        TextField {
            id: filePathField
            width: parent.width - 230
            placeholderText: qsTr("Select file or folder path...")
            readOnly: true
            leftPadding: 12
            rightPadding: 12
            color: root.darkMode ? "#ffffff" : "#000000"
            background: Rectangle {
                color: root.darkMode ? "#2d2d2d" : "#ffffff"
                border.color: root.darkMode ? "#546e7a" : "#cccccc"
                border.width: 1
                radius: 4
            }
        }

        Button {
            text: qsTr("📂 Browse")
            width: 100
            onClicked: root.browseRequested()
        }

        Button {
            text: qsTr("📑 Batch")
            width: 100
            onClicked: root.batchSelectRequested()
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Select multiple files (Ctrl+B)")
        }
    }

    // Progress Bar Section
    Column {
        spacing: 10
        width: parent.width
        topPadding: 15
        visible: fileProgressBar.visible

        Label {
            text: qsTr("⏳ Operation Progress:")
            font.bold: true
        }

        ProgressBar {
            id: fileProgressBar
            width: parent.width
            from: 0
            to: 100
            value: 0
            visible: false

            background: Rectangle {
                color: "#e9ecef"
                border.color: "#dee2e6"
                border.width: 1
                radius: 4
            }

            contentItem: Item {
                Rectangle {
                    width: fileProgressBar.visualPosition * parent.width
                    height: parent.height
                    color: fileProgressBar.value < 100 ? "#007bff" : "#28a745"
                    radius: 4
                }
            }
        }

        Label {
            id: progressStatus
            text: ""
            font.pixelSize: 12
            color: "#666666"
        }
    }

    // Operation Buttons
    Row {
        spacing: 15
        anchors.horizontalCenter: parent.horizontalCenter
        topPadding: 10

        Button {
            id: encryptButton
            text: qsTr("🔐 Encrypt File")
            enabled: !fileProgressBar.visible && root.filePath.trim() !== ""
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Encrypt single file (Ctrl+E)")
            // Click handler will be connected from parent
        }

        Button {
            id: batchEncryptButton
            text: qsTr("📦 Batch Encrypt")
            enabled: !fileProgressBar.visible && root.selectedFiles.length > 0
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Encrypt " + root.selectedFiles.length + " files")
            onClicked: {
                PostQuantumCrypto.startBatchEncryption()
                batchProgressDialog.open()
            }
        }

        Button {
            id: decryptButton
            text: qsTr("🔓 Decrypt File")
            enabled: !fileProgressBar.visible && root.filePath.trim() !== ""
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Decrypt single file (Ctrl+D)")
            // Click handler will be connected from parent
        }

        Button {
            id: batchDecryptButton
            text: qsTr("📦 Batch Decrypt")
            enabled: !fileProgressBar.visible && root.selectedFiles.length > 0
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Decrypt " + root.selectedFiles.length + " files")
            onClicked: {
                PostQuantumCrypto.startBatchDecryption()
                batchProgressDialog.open()
            }
        }
    }

    // Status Labels
    Label {
        id: fileStatus
        text: qsTr("Select a file or folder to begin encryption/decryption operations.")
        wrapMode: Text.WordWrap
        width: parent.width
        color: root.darkMode ? "#b0b0b0" : "#666666"
        font.pixelSize: 12
    }

    Label {
        id: batchStatus
        text: root.selectedFiles.length > 0 ? ("📑 " + root.selectedFiles.length + " files selected for batch processing") : ""
        wrapMode: Text.WordWrap
        width: parent.width
        font.pixelSize: 12
        font.bold: root.selectedFiles.length > 0
        color: root.darkMode ? "#90caf9" : "#2196f3"
        visible: root.selectedFiles.length > 0
    }

    // Keyboard Shortcuts Info
    Rectangle {
        width: parent.width
        height: shortcutsLabel.height + 16
        color: root.darkMode ? "#2d2d2d" : "#f5f5f5"
        border.color: root.darkMode ? "#546e7a" : "#e0e0e0"
        border.width: 1
        radius: 4

        Label {
            id: shortcutsLabel
            anchors.centerIn: parent
            text: "⌨️ Shortcuts: Ctrl+E (Encrypt) | Ctrl+D (Decrypt) | Ctrl+B (Batch Select) | Ctrl+T (Dark Mode)"
            font.pixelSize: 11
            color: root.darkMode ? "#b0b0b0" : "#666666"
        }
    }

    // Batch Progress Dialog
    BatchDialog.BatchProgressDialog {
        id: batchProgressDialog
        darkMode: root.darkMode
    }

    // Public functions for updating UI
    function setFileStatus(message, color) {
        fileStatus.text = message
        fileStatus.color = color
    }

    function setBatchStatus(message, color) {
        batchStatus.text = message
        batchStatus.color = color
    }

    function setProgress(value, status) {
        fileProgressBar.value = value
        progressStatus.text = status
    }

    function showProgress() {
        fileProgressBar.visible = true
        fileProgressBar.value = 0
    }

    function hideProgress() {
        fileProgressBar.visible = false
        progressStatus.text = ""
    }

    // Expose buttons for parent to connect handlers
    property alias encryptButtonAlias: encryptButton
    property alias decryptButtonAlias: decryptButton
    property alias batchEncryptButtonAlias: batchEncryptButton
    property alias batchDecryptButtonAlias: batchDecryptButton
}
