import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs
import CybouWallet 1.0

ApplicationWindow {
    id: mainWindow
    width: 960
    height: 600
    visible: true
    title: qsTr("cybou - Post-Quantum File & Text Encryption")

    property bool mnemonicAccepted: false
    property string lastTextOperation: "" // "encrypt" or "decrypt"
    property bool darkMode: false
    property var selectedFiles: []

    // Keyboard shortcuts
    Shortcut {
        sequence: "Ctrl+E"
        onActivated: if (tabBar.currentIndex === 1 && encryptButton.enabled) encryptButton.clicked()
    }
    Shortcut {
        sequence: "Ctrl+D"
        onActivated: if (tabBar.currentIndex === 1 && decryptButton.enabled) decryptButton.clicked()
    }
    Shortcut {
        sequence: "Ctrl+T"
        onActivated: if (darkMode) darkMode = false; else darkMode = true
    }
    Shortcut {
        sequence: "Ctrl+B"
        onActivated: if (tabBar.currentIndex === 1) batchFileDialog.open()
    }

    // Helper function to convert file:// URLs to local paths (cross-platform)
    function urlToLocalPath(urlString) {
        var url = urlString.toString()
        // Remove file:// prefix and handle Windows/Linux differences
        if (url.startsWith("file:///")) {
            // Windows: file:///C:/path -> C:/path
            // Linux: file:///home/path -> /home/path
            url = url.substring(8) // Remove "file:///"
            // On Windows, we get the correct path. On Linux, add back leading /
            if (Qt.platform.os !== "windows" && !url.startsWith("/")) {
                url = "/" + url
            }
        } else if (url.startsWith("file://")) {
            url = url.substring(7) // Remove "file://"
            if (Qt.platform.os !== "windows" && !url.startsWith("/")) {
                url = "/" + url
            }
        }
        return url
    }

    Component.onCompleted: splashDialog.open()

    Connections {
        target: PostQuantumCrypto
        function onOperationProgress(operation, progress, status) {
            if (operation === "encryptFile" || operation === "decryptFile") {
                fileProgressBar.value = progress
                progressStatus.text = status
            }
        }
    }

    FileDialog {
        id: fileDialog
        title: "Select file or folder to encrypt/decrypt"
        fileMode: FileDialog.OpenFile
        onAccepted: {
            filePath.text = urlToLocalPath(fileDialog.selectedFile)
        }
    }

    FileDialog {
        id: batchFileDialog
        title: "Select multiple files for batch processing"
        fileMode: FileDialog.OpenFiles
        onAccepted: {
            selectedFiles = []
            for (var i = 0; i < batchFileDialog.selectedFiles.length; i++) {
                selectedFiles.push(urlToLocalPath(batchFileDialog.selectedFiles[i]))
            }
            batchStatus.text = selectedFiles.length + " files selected for batch processing"
            batchStatus.color = darkMode ? "#90caf9" : "blue"
        }
    }

    FileDialog {
        id: saveTextDialog
        title: "Save encrypted text as .cybou file"
        fileMode: FileDialog.SaveFile
        nameFilters: ["cybou files (*.cybou)", "All files (*)"]
        defaultSuffix: "cybou"
        onAccepted: {
            var filePath = urlToLocalPath(saveTextDialog.selectedFile)
            if (PostQuantumCrypto.saveEncryptedTextToFile(outputText.text, filePath)) {
                statusLabel.text = qsTr("Text saved to file successfully")
                statusLabel.color = darkMode ? "#81c784" : "green"
            } else {
                statusLabel.text = qsTr("Failed to save text to file")
                statusLabel.color = darkMode ? "#ef5350" : "red"
            }
        }
    }

    FileDialog {
        id: loadTextDialog
        title: "Load encrypted text from .cybou file"
        fileMode: FileDialog.OpenFile
        nameFilters: ["cybou files (*.cybou)", "All files (*)"]
        onAccepted: {
            var filePath = urlToLocalPath(loadTextDialog.selectedFile)
            var content = PostQuantumCrypto.loadEncryptedTextFromFile(filePath)
            if (content !== "") {
                inputText.text = content
                statusLabel.text = qsTr("Text loaded from file successfully")
                statusLabel.color = darkMode ? "#81c784" : "green"
            } else {
                statusLabel.text = qsTr("Failed to load text from file")
                statusLabel.color = darkMode ? "#ef5350" : "red"
            }
        }
    }

    // Splash dialog for mnemonic setup
    SplashDialog {
        id: splashDialog
        onMnemonicAccepted: {
            mnemonicAccepted = true
            splashDialog.close()
        }
    }

    // Main content area - only shown after mnemonic setup
    ColumnLayout {
        anchors.fill: parent
        visible: mnemonicAccepted
        spacing: 0

        // Header with title and dark mode toggle
        Rectangle {
            Layout.fillWidth: true
            height: 60
            color: darkMode ? "#2d2d2d" : "#f5f5f5"
            border.color: darkMode ? "#404040" : "#e0e0e0"
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.margins: 10
                spacing: 10

                Label {
                    text: qsTr("🔐 cybou - Post-Quantum Encryption")
                    font.pixelSize: 18
                    font.bold: true
                    color: darkMode ? "#ffffff" : "#000000"
                    Layout.fillWidth: true
                }

                Button {
                    text: darkMode ? "☀️ Light" : "🌙 Dark"
                    onClicked: darkMode = !darkMode
                    font.pixelSize: 12
                    Layout.preferredWidth: 80
                }
            }
        }

        // Tab bar for different operations
        TabBar {
            id: tabBar
            Layout.fillWidth: true
            height: 40

            TabButton {
                text: qsTr("📝 Text")
                font.pixelSize: 14
            }
            TabButton {
                text: qsTr("📁 Files")
                font.pixelSize: 14
            }
            TabButton {
                text: qsTr("✍️ Signatures")
                font.pixelSize: 14
            }
            TabButton {
                text: qsTr("🔑 Keys")
                font.pixelSize: 14
            }
        }

        // Tab content area
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabBar.currentIndex

            // Text Encryption Tab
            TextEncryptionTab {
                darkMode: mainWindow.darkMode
                lastTextOperation: mainWindow.lastTextOperation
                onSaveTextRequested: saveTextDialog.open()
                onLoadTextRequested: loadTextDialog.open()
            }

            // File Encryption Tab
            FileEncryptionTab {
                darkMode: mainWindow.darkMode
                selectedFiles: mainWindow.selectedFiles
                onBrowseRequested: fileDialog.open()
                onBatchSelectRequested: batchFileDialog.open()
                onFilesDropped: function(files) {
                    selectedFiles = files
                    batchStatus.text = files.length + " files selected for batch processing"
                    batchStatus.color = darkMode ? "#90caf9" : "blue"
                }
            }

            // Signature Tab
            SignatureTab {
                darkMode: mainWindow.darkMode
            }

            // Key Management Tab
            KeyManagementTab {
                darkMode: mainWindow.darkMode
            }
        }

        // Status bar at bottom
        Rectangle {
            Layout.fillWidth: true
            height: 30
            color: darkMode ? "#1e1e1e" : "#f0f0f0"
            border.color: darkMode ? "#404040" : "#e0e0e0"
            border.width: 1

            Label {
                id: statusLabel
                anchors.centerIn: parent
                text: qsTr("Ready")
                font.pixelSize: 12
                color: darkMode ? "#cccccc" : "#666666"
            }
        }
    }

    // Setup required message - shown before mnemonic is set
    Column {
        anchors.centerIn: parent
        spacing: 16
        visible: !mnemonicAccepted

        Label {
            text: qsTr("🔐 cybou Setup Required")
            font.pixelSize: 20
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            width: parent.width * 0.8
        }

        Label {
            text: qsTr("Please complete the mnemonic setup in the dialog that appeared.\n\nYour cybou post-quantum encryptor will be ready for secure file and text encryption operations.")
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
            width: parent.width * 0.8
            color: "#666666"
        }
    }
}