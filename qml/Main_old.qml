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

    FileDialog {
        id: saveTextDialog
        title: "Save encrypted text as .cybou file"
        fileMode: FileDialog.SaveFile
        nameFilters: ["cybou files (*.cybou)", "All files (*)"]
        defaultSuffix: "cybou"
        onAccepted: {
            var filePath = urlToLocalPath(saveTextDialog.selectedFile)
            if (PostQuantumCrypto.saveEncryptedTextToFile(outputText.text, filePath)) {
                textStatus.text = qsTr("💾 Text saved to: ") + filePath
                textStatus.color = "green"
            } else {
                textStatus.text = qsTr("❌ Failed to save file!")
                textStatus.color = "red"
            }
        }
    }

    FileDialog {
        id: loadTextDialog
        title: "Load .cybou file to decrypt"
        fileMode: FileDialog.OpenFile
        nameFilters: ["cybou files (*.cybou)", "All files (*)"]
        onAccepted: {
            var filePath = urlToLocalPath(loadTextDialog.selectedFile)
            var content = PostQuantumCrypto.loadEncryptedTextFromFile(filePath)
            if (content !== "") {
                inputText.text = content
                textStatus.text = qsTr("📂 File loaded: ") + filePath
                textStatus.color = "blue"
            } else {
                textStatus.text = qsTr("❌ Failed to load file!")
                textStatus.color = "red"
            }
        }
    }

    FileDialog {
        id: savePublicKeyDialog
        title: "Save public key to file"
        fileMode: FileDialog.SaveFile
        nameFilters: ["cyboukey files (*.cyboukey)", "Text files (*.txt)", "All files (*)"]
        defaultSuffix: "cyboukey"
        onAccepted: {
            var filePath = urlToLocalPath(savePublicKeyDialog.selectedFile)
            // Save the public key to file
            if (PostQuantumCrypto.saveEncryptedTextToFile(publicKeyDisplay.text, filePath)) {
                keyStatus.text = qsTr("💾 Public key saved to: ") + filePath
                keyStatus.color = "green"
            } else {
                keyStatus.text = qsTr("❌ Failed to save public key!")
                keyStatus.color = "red"
            }
        }
    }

    FileDialog {
        id: saveSignatureDialog
        title: "Save signature to file"
        fileMode: FileDialog.SaveFile
        nameFilters: ["cybousig files (*.cybousig)", "Text files (*.txt)", "All files (*)"]
        defaultSuffix: "cybousig"
        onAccepted: {
            var filePath = urlToLocalPath(saveSignatureDialog.selectedFile)
            if (PostQuantumCrypto.saveEncryptedTextToFile(signatureOutput.text, filePath)) {
                signatureStatus.text = qsTr("💾 Signature saved to: ") + filePath
                signatureStatus.color = "green"
            } else {
                signatureStatus.text = qsTr("❌ Failed to save signature!")
                signatureStatus.color = "red"
            }
        }
    }

    FileDialog {
        id: loadSignatureDialog
        title: "Load signature from file"
        fileMode: FileDialog.OpenFile
        nameFilters: ["cybousig files (*.cybousig)", "Text files (*.txt)", "All files (*)"]
        onAccepted: {
            var filePath = urlToLocalPath(loadSignatureDialog.selectedFile)
            var content = PostQuantumCrypto.loadEncryptedTextFromFile(filePath)
            if (content !== "") {
                signatureOutput.text = content
                signatureStatus.text = qsTr("📂 Signature loaded from: ") + filePath
                signatureStatus.color = "blue"
            } else {
                signatureStatus.text = qsTr("❌ Failed to load signature!")
                signatureStatus.color = "red"
            }
        }
    }

    FileDialog {
        id: savePrivateKeyDialog
        title: "Save private key to file (ENCRYPTED)"
        fileMode: FileDialog.SaveFile
        nameFilters: ["cyboukey files (*.cyboukey)", "Text files (*.txt)", "All files (*)"]
        defaultSuffix: "cyboukey"
        onAccepted: {
            var filePath = urlToLocalPath(savePrivateKeyDialog.selectedFile)
            // Export and save the private key
            var privateKey = PostQuantumCrypto.exportPrivateKey()
            if (privateKey !== "") {
                if (PostQuantumCrypto.saveEncryptedTextToFile(privateKey, filePath)) {
                    keyStatus.text = qsTr("💾 Private key saved to: ") + filePath
                    keyStatus.color = "green"
                } else {
                    keyStatus.text = qsTr("❌ Failed to save private key!")
                    keyStatus.color = "red"
                }
            } else {
                keyStatus.text = qsTr("❌ No private key available!")
                keyStatus.color = "red"
            }
        }
    }

    FileDialog {
        id: loadKeyPairDialog
        title: "Load key pair from file"
        fileMode: FileDialog.OpenFile
        nameFilters: ["cyboukey files (*.cyboukey)", "Text files (*.txt)", "All files (*)"]
        onAccepted: {
            var filePath = urlToLocalPath(loadKeyPairDialog.selectedFile)
            var content = PostQuantumCrypto.loadEncryptedTextFromFile(filePath)
            if (content !== "") {
                // Try to parse the content as private key + public key
                var lines = content.split('\n')
                if (lines.length >= 2) {
                    var privateKey = lines[0].trim()
                    var publicKey = lines[1].trim()
                    
                    if (PostQuantumCrypto.importKeyPair(privateKey, publicKey)) {
                        publicKeyDisplay.text = PostQuantumCrypto.publicKey
                        keyStatus.text = qsTr("✅ Key pair imported from: ") + filePath
                        keyStatus.color = "green"
                    } else {
                        keyStatus.text = qsTr("❌ Failed to import key pair!")
                        keyStatus.color = "red"
                    }
                } else {
                    keyStatus.text = qsTr("❌ Invalid key file format!")
                    keyStatus.color = "red"
                }
            } else {
                keyStatus.text = qsTr("❌ Failed to load key file!")
                keyStatus.color = "red"
            }
        }
    }

    SplashDialog {
        id: splashDialog
        modal: true
        onMnemonicValidated: function(mnemonic) {
            mnemonicAccepted = true
            mainWindow.title = qsTr("cybou - Ready for Encryption")
        }
    }

    header: ToolBar {
        anchors.margins: 20
        background: Rectangle {
            color: darkMode ? "#2d2d2d" : "#f5f5f5"
        }

        Label {
            text: qsTr("cybou")
            anchors.verticalCenter: parent.verticalCenter
            font.bold: true
            leftPadding: 12
            color: darkMode ? "#ffffff" : "#000000"
        }

        Row {
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 8

            ToolButton {
                text: darkMode ? "☀️" : "🌙"
                onClicked: darkMode = !darkMode
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Toggle Dark Mode (Ctrl+T)")
            }

            Label {
                text: mnemonicAccepted ? qsTr("🔐 PQ Keys Active") : qsTr("🔓 Setup Required")
                color: mnemonicAccepted ? (darkMode ? "#4caf50" : "green") : "orange"
                font.pixelSize: 12
            }

            Button {
                text: qsTr("🔄 Change Mnemonic")
                visible: mnemonicAccepted
                onClicked: splashDialog.open()
            }
        }
    }

    // Main content - only visible after mnemonic is set
    TabBar {
        id: tabBar
        width: parent.width
        visible: mnemonicAccepted

        TabButton {
            text: qsTr("📝 Text Encryption")
        }
        TabButton {
            text: qsTr("📁 File Encryption")
        }
        TabButton {
            text: qsTr("✍️ Digital Signatures")
        }
        TabButton {
            text: qsTr("🔑 Key Management")
        }
    }

    StackLayout {
        width: parent.width
        height: parent.height - tabBar.height - header.height
        currentIndex: tabBar.currentIndex
        visible: mnemonicAccepted

        // Text Encryption Tab
        Column {
            spacing: 20
            width: parent.width * 0.85

            Label {
                text: qsTr("🔤 Text Encryption/Decryption")
                font.pixelSize: 20
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
                width: parent.width
            }

            Label {
                text: qsTr("🚀 'In a world where quantum computers threaten everything, cybou keeps your secrets safe!'")
                font.pixelSize: 12
                horizontalAlignment: Text.AlignHCenter
                width: parent.width
                color: "#666666"
                font.italic: true
            }

            // Input Section
            Column {
                spacing: 12
                width: parent.width

                Label {
                    text: qsTr("📝 Input Text:")
                    font.bold: true
                }

                TextArea {
                    id: inputText
                    width: parent.width
                    height: 120
                    placeholderText: qsTr("Enter text to encrypt... (Your secrets are quantum-safe here! 🔐)")
                    wrapMode: TextArea.Wrap
                    leftPadding: 12
                    rightPadding: 12
                    topPadding: 10
                    bottomPadding: 10
                    background: Rectangle {
                        color: "#e8f4fd"  // Light blue background for input
                        border.color: "#4a90e2"
                        border.width: 1
                        radius: 4
                    }
                }

                Row {
                    spacing: 12
                    anchors.right: parent.right
                    topPadding: 8

                    Button {
                        text: qsTr("📋 Paste")
                        onClicked: {
                            inputText.text = ""
                            inputText.paste()
                        }
                    }

                    Button {
                        text: qsTr("🗑️ Clear")
                        onClicked: {
                            inputText.text = ""
                        }
                    }
                }
            }

            Row {
                spacing: 15
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 10

                Button {
                    text: qsTr("🔐 Encrypt Text")
                    onClicked: {
                        if (inputText.text.trim() !== "") {
                            var result = PostQuantumCrypto.encryptText(inputText.text)
                            if (result !== "") {
                                outputText.text = result
                                lastTextOperation = "encrypt"
                                textStatus.text = qsTr("✅ Text encrypted successfully!")
                                textStatus.color = "green"
                            } else {
                                textStatus.text = qsTr("❌ Encryption failed!")
                                textStatus.color = "red"
                            }
                        } else {
                            textStatus.text = qsTr("⚠️ Please enter text to encrypt")
                            textStatus.color = "orange"
                        }
                    }
                }

                Button {
                    text: qsTr("🔓 Decrypt Text")
                    onClicked: {
                        if (inputText.text.trim() !== "") {
                            var result = PostQuantumCrypto.decryptText(inputText.text)
                            if (result !== "") {
                                outputText.text = result
                                lastTextOperation = "decrypt"
                                textStatus.text = qsTr("✅ Text decrypted successfully!")
                                textStatus.color = "green"
                            } else {
                                textStatus.text = qsTr("❌ Decryption failed!")
                                textStatus.color = "red"
                            }
                        } else {
                            textStatus.text = qsTr("⚠️ Please enter text to decrypt")
                            textStatus.color = "orange"
                        }
                    }
                }
            }

            // Output Section
            Column {
                spacing: 12
                width: parent.width
                topPadding: 10

                Label {
                    text: qsTr("📄 Output Text:")
                    font.bold: true
                }

                TextArea {
                    id: outputText
                    width: parent.width
                    height: 120
                    placeholderText: qsTr("Encrypted/decrypted result will appear here...")
                    readOnly: true
                    wrapMode: TextArea.Wrap
                    selectByMouse: true
                    leftPadding: 12
                    rightPadding: 12
                    topPadding: 10
                    bottomPadding: 10
                    background: Rectangle {
                        color: outputText.text === "" ? "#f8f9fa" :  // Neutral gray when empty
                               (lastTextOperation === "encrypt" ? "#e8f5e8" :  // Light green for encryption
                               (lastTextOperation === "decrypt" ? "#fce8e6" : "#f8f9fa"))  // Light red for decryption, neutral otherwise
                        border.color: outputText.text === "" ? "#dee2e6" :
                                     (lastTextOperation === "encrypt" ? "#4caf50" :
                                     (lastTextOperation === "decrypt" ? "#f44336" : "#dee2e6"))
                        border.width: 1
                        radius: 4
                    }
                }

                Row {
                    spacing: 12
                    anchors.right: parent.right
                    topPadding: 8

                    Button {
                        text: qsTr("📋 Copy")
                        enabled: outputText.text !== ""
                        onClicked: {
                            outputText.selectAll()
                            outputText.copy()
                            textStatus.text = qsTr("📋 Copied to clipboard!")
                            textStatus.color = "blue"
                        }
                    }

                    Button {
                        text: qsTr("💾 Save as .cybou")
                        enabled: outputText.text !== ""
                        onClicked: {
                            saveTextDialog.open()
                        }
                    }

                    Button {
                        text: qsTr("📂 Load .cybou")
                        onClicked: {
                            loadTextDialog.open()
                        }
                    }

                    Button {
                        text: qsTr("🗑️ Clear")
                        onClicked: {
                            outputText.text = ""
                            lastTextOperation = ""
                            textStatus.text = ""
                        }
                    }
                }
            }

            Label {
                id: textStatus
                text: ""
                wrapMode: Text.WordWrap
                width: parent.width
                font.pixelSize: 12
                topPadding: 10
            }
        }

        // File Encryption Tab
        Column {
            spacing: 20
            width: parent.width * 0.85

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
                color: dragArea.containsDrag ? (darkMode ? "#2c3e50" : "#e3f2fd") : (darkMode ? "#1e1e1e" : "#f5f5f5")
                border.color: darkMode ? "#546e7a" : "#90caf9"
                border.width: 2
                radius: 8
                Layout.topMargin: 10

                DropArea {
                    id: dragArea
                    anchors.fill: parent
                    onDropped: function(drop) {
                        if (drop.hasUrls) {
                            var urls = drop.urls
                            if (urls.length === 1) {
                                filePath.text = urlToLocalPath(urls[0])
                                fileStatus.text = "✅ File ready: " + filePath.text
                                fileStatus.color = darkMode ? "#4caf50" : "green"
                            } else if (urls.length > 1) {
                                selectedFiles = []
                                for (var i = 0; i < urls.length; i++) {
                                    selectedFiles.push(urlToLocalPath(urls[i]))
                                }
                                batchStatus.text = urls.length + " files dropped for batch processing"
                                batchStatus.color = darkMode ? "#90caf9" : "blue"
                            }
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
                            color: darkMode ? "#ffffff" : "#000000"
                        }

                        Label {
                            text: "or use the browse button below"
                            font.pixelSize: 12
                            anchors.horizontalCenter: parent.horizontalCenter
                            color: darkMode ? "#b0b0b0" : "#666666"
                        }

                        Label {
                            text: "💡 Multiple files = batch mode"
                            font.pixelSize: 11
                            font.italic: true
                            anchors.horizontalCenter: parent.horizontalCenter
                            color: darkMode ? "#90caf9" : "#2196f3"
                        }
                    }
                }
            }

            Row {
                spacing: 12
                width: parent.width
                topPadding: 10

                TextField {
                    id: filePath
                    width: parent.width - 230
                    leftPadding: 12
                    rightPadding: 12
                    placeholderText: qsTr("Select file or folder path...")
                    readOnly: true
                    color: darkMode ? "#ffffff" : "#000000"
                    background: Rectangle {
                        color: darkMode ? "#2d2d2d" : "#ffffff"
                        border.color: darkMode ? "#546e7a" : "#cccccc"
                        border.width: 1
                        radius: 4
                    }
                }

                Button {
                    text: qsTr("📂 Browse")
                    width: 100
                    onClicked: {
                        fileDialog.open()
                    }
                }

                Button {
                    text: qsTr("📑 Batch")
                    width: 100
                    onClicked: {
                        batchFileDialog.open()
                    }
                    ToolTip.visible: hovered
                    ToolTip.text: qsTr("Select multiple files (Ctrl+B)")
                }
            }

            // Progress Bar for file operations
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
                            color: fileProgressBar.value < 100 ? "#007bff" : "#28a745"  // Blue during operation, green when complete
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

            Row {
                spacing: 15
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 10

                Button {
                    id: encryptButton
                    text: qsTr("🔐 Encrypt File")
                    enabled: !fileProgressBar.visible && filePath.text.trim() !== ""
                    ToolTip.visible: hovered
                    ToolTip.text: qsTr("Encrypt single file (Ctrl+E)")
                    onClicked: {
                        if (filePath.text.trim() !== "") {
                            fileProgressBar.visible = true
                            fileProgressBar.value = 0
                            progressStatus.text = "Starting encryption..."
                            fileStatus.text = "Preparing encryption..."

                            // Generate output path with .cybou extension
                            var inputPath = filePath.text
                            var outputPath = inputPath + ".cybou"

                            fileStatus.text = "Encrypting: " + inputPath + " -> " + outputPath
                            fileStatus.color = darkMode ? "#2196f3" : "blue"

                            try {
                                var success = PostQuantumCrypto.encryptFile(inputPath, outputPath)
                                if (success) {
                                    fileStatus.text = "✅ Encryption completed: " + outputPath
                                    fileStatus.color = darkMode ? "#4caf50" : "green"
                                } else {
                                    fileStatus.text = "❌ Encryption failed! Check if file exists and you have write permissions."
                                    fileStatus.color = darkMode ? "#f44336" : "red"
                                }
                            } catch (error) {
                                fileStatus.text = "❌ Error: " + error.message
                                fileStatus.color = darkMode ? "#f44336" : "red"
                            }

                            fileProgressBar.visible = false
                            progressStatus.text = ""
                        } else {
                            fileStatus.text = "⚠️ Please select a file first"
                            fileStatus.color = "orange"
                        }
                    }
                }

                Button {
                    text: qsTr("📦 Batch Encrypt")
                    enabled: !fileProgressBar.visible && selectedFiles.length > 0
                    ToolTip.visible: hovered
                    ToolTip.text: qsTr("Encrypt " + selectedFiles.length + " files")
                    onClicked: {
                        fileProgressBar.visible = true
                        fileProgressBar.value = 0
                        var successCount = 0
                        var failCount = 0
                        
                        for (var i = 0; i < selectedFiles.length; i++) {
                            fileProgressBar.value = (i / selectedFiles.length) * 100
                            progressStatus.text = "Encrypting file " + (i + 1) + " of " + selectedFiles.length
                            
                            var inputPath = selectedFiles[i]
                            var outputPath = inputPath + ".cybou"
                            
                            try {
                                if (PostQuantumCrypto.encryptFile(inputPath, outputPath)) {
                                    successCount++
                                } else {
                                    failCount++
                                }
                            } catch (error) {
                                failCount++
                            }
                        }
                        
                        fileProgressBar.value = 100
                        fileProgressBar.visible = false
                        progressStatus.text = ""
                        batchStatus.text = "✅ Batch complete: " + successCount + " succeeded, " + failCount + " failed"
                        batchStatus.color = failCount === 0 ? (darkMode ? "#4caf50" : "green") : "orange"
                    }
                }

                Button {
                    id: decryptButton
                    text: qsTr("🔓 Decrypt File")
                    enabled: !fileProgressBar.visible && filePath.text.trim() !== ""
                    ToolTip.visible: hovered
                    ToolTip.text: qsTr("Decrypt single file (Ctrl+D)")
                    onClicked: {
                        if (filePath.text.trim() !== "") {
                            fileProgressBar.visible = true
                            fileProgressBar.value = 0
                            progressStatus.text = "Starting decryption..."
                            fileStatus.text = "Preparing decryption..."

                            var inputPath = filePath.text

                            // Check if it's a .cybou file
                            if (!inputPath.endsWith(".cybou")) {
                                fileProgressBar.visible = false
                                progressStatus.text = ""
                                fileStatus.text = "⚠️ Selected file is not a .cybou encrypted file. Please select a .cybou file."
                                fileStatus.color = "orange"
                                return
                            }

                            // Generate output path by removing .cybou and adding _decrypted
                            var baseName = inputPath.substring(0, inputPath.length - 6) // Remove .cybou
                            var outputPath = baseName + "_decrypted"

                            // If the original file had an extension, restore it
                            var lastDot = baseName.lastIndexOf(".")
                            if (lastDot !== -1) {
                                var namePart = baseName.substring(0, lastDot)
                                var extPart = baseName.substring(lastDot)
                                outputPath = namePart + "_decrypted" + extPart
                            }

                            fileStatus.text = "Decrypting: " + inputPath + " -> " + outputPath
                            fileStatus.color = darkMode ? "#2196f3" : "blue"

                            try {
                                var success = PostQuantumCrypto.decryptFile(inputPath, outputPath)
                                if (success) {
                                    fileStatus.text = "✅ Decryption completed: " + outputPath
                                    fileStatus.color = darkMode ? "#4caf50" : "green"
                                } else {
                                    fileStatus.text = "❌ Decryption failed! File may be corrupted or use a different mnemonic."
                                    fileStatus.color = darkMode ? "#f44336" : "red"
                                }
                            } catch (error) {
                                fileStatus.text = "❌ Error: " + error.message
                                fileStatus.color = darkMode ? "#f44336" : "red"
                            }

                            fileProgressBar.visible = false
                            progressStatus.text = ""
                        } else {
                            fileStatus.text = "⚠️ Please select a .cybou file first"
                            fileStatus.color = "orange"
                        }
                    }
                }

                Button {
                    text: qsTr("📦 Batch Decrypt")
                    enabled: !fileProgressBar.visible && selectedFiles.length > 0
                    ToolTip.visible: hovered
                    ToolTip.text: qsTr("Decrypt " + selectedFiles.length + " files")
                    onClicked: {
                        fileProgressBar.visible = true
                        fileProgressBar.value = 0
                        var successCount = 0
                        var failCount = 0
                        
                        for (var i = 0; i < selectedFiles.length; i++) {
                            fileProgressBar.value = (i / selectedFiles.length) * 100
                            progressStatus.text = "Decrypting file " + (i + 1) + " of " + selectedFiles.length
                            
                            var inputPath = selectedFiles[i]
                            
                            // Skip non-.cybou files
                            if (!inputPath.endsWith(".cybou")) {
                                failCount++
                                continue
                            }
                            
                            var baseName = inputPath.substring(0, inputPath.length - 6)
                            var outputPath = baseName + "_decrypted"
                            var lastDot = baseName.lastIndexOf(".")
                            if (lastDot !== -1) {
                                var namePart = baseName.substring(0, lastDot)
                                var extPart = baseName.substring(lastDot)
                                outputPath = namePart + "_decrypted" + extPart
                            }
                            
                            try {
                                if (PostQuantumCrypto.decryptFile(inputPath, outputPath)) {
                                    successCount++
                                } else {
                                    failCount++
                                }
                            } catch (error) {
                                failCount++
                            }
                        }
                        
                        fileProgressBar.value = 100
                        fileProgressBar.visible = false
                        progressStatus.text = ""
                        batchStatus.text = "✅ Batch complete: " + successCount + " succeeded, " + failCount + " failed"
                        batchStatus.color = failCount === 0 ? (darkMode ? "#4caf50" : "green") : "orange"
                    }
                }
            }

            Label {
                id: fileStatus
                text: qsTr("Select a file or folder to begin encryption/decryption operations.")
                wrapMode: Text.WordWrap
                width: parent.width
                color: darkMode ? "#b0b0b0" : "#666666"
                font.pixelSize: 12
            }

            Label {
                id: batchStatus
                text: selectedFiles.length > 0 ? ("📑 " + selectedFiles.length + " files selected for batch processing") : ""
                wrapMode: Text.WordWrap
                width: parent.width
                font.pixelSize: 12
                font.bold: selectedFiles.length > 0
                color: darkMode ? "#90caf9" : "#2196f3"
                visible: selectedFiles.length > 0
            }

            // Keyboard shortcuts info
            Rectangle {
                width: parent.width
                height: shortcutsLabel.height + 16
                color: darkMode ? "#2d2d2d" : "#f5f5f5"
                border.color: darkMode ? "#546e7a" : "#e0e0e0"
                border.width: 1
                radius: 4

                Label {
                    id: shortcutsLabel
                    anchors.centerIn: parent
                    text: "⌨️ Shortcuts: Ctrl+E (Encrypt) | Ctrl+D (Decrypt) | Ctrl+B (Batch Select) | Ctrl+T (Dark Mode)"
                    font.pixelSize: 11
                    color: darkMode ? "#b0b0b0" : "#666666"
                }
            }
        }

        // Digital Signatures Tab
        Column {
            spacing: 20
            width: parent.width * 0.85

            Label {
                text: qsTr("✍️ Digital Signatures")
                font.pixelSize: 20
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
                width: parent.width
            }

            Label {
                text: qsTr("🔏 'Sign your messages with quantum-resistant cryptography - authenticity guaranteed!'")
                font.pixelSize: 12
                horizontalAlignment: Text.AlignHCenter
                width: parent.width
                color: "#666666"
                font.italic: true
            }

            // Message Input Section
            Column {
                spacing: 12
                width: parent.width

                Label {
                    text: qsTr("📝 Message to Sign:")
                    font.bold: true
                }

                TextArea {
                    id: signMessageText
                    width: parent.width
                    height: 120
                    placeholderText: qsTr("Enter message to sign with ML-DSA-65...")
                    wrapMode: TextArea.Wrap
                    leftPadding: 12
                    rightPadding: 12
                    topPadding: 10
                    bottomPadding: 10
                    background: Rectangle {
                        color: "#fff3cd"  // Light yellow background for signing
                        border.color: "#ffc107"
                        border.width: 1
                        radius: 4
                    }
                }

                Row {
                    spacing: 10
                    anchors.right: parent.right

                    Button {
                        text: qsTr("📋 Paste")
                        onClicked: {
                            signMessageText.text = ""
                            signMessageText.paste()
                        }
                    }

                    Button {
                        text: qsTr("🗑️ Clear")
                        onClicked: {
                            signMessageText.text = ""
                        }
                    }
                }
            }

            Row {
                spacing: 15
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 10

                Button {
                    text: qsTr("✍️ Sign Message")
                    onClicked: {
                        if (signMessageText.text.trim() !== "") {
                            var signature = PostQuantumCrypto.signMessage(signMessageText.text)
                            if (signature !== "") {
                                signatureOutput.text = signature
                                signatureStatus.text = qsTr("✅ Message signed successfully with ML-DSA-65!")
                                signatureStatus.color = "green"
                            } else {
                                signatureStatus.text = qsTr("❌ Signing failed!")
                                signatureStatus.color = "red"
                            }
                        } else {
                            signatureStatus.text = qsTr("⚠️ Please enter a message to sign")
                            signatureStatus.color = "orange"
                        }
                    }
                }

                Button {
                    text: qsTr("🔍 Verify Signature")
                    onClicked: {
                        if (signMessageText.text.trim() !== "" && signatureOutput.text.trim() !== "") {
                            var publicKey = PostQuantumCrypto.publicKey
                            if (publicKey !== "") {
                                var isValid = PostQuantumCrypto.verifySignature(signMessageText.text, signatureOutput.text, publicKey)
                                if (isValid) {
                                    signatureStatus.text = qsTr("✅ Signature verified successfully!")
                                    signatureStatus.color = "green"
                                } else {
                                    signatureStatus.text = qsTr("❌ Signature verification failed!")
                                    signatureStatus.color = "red"
                                }
                            } else {
                                signatureStatus.text = qsTr("❌ No public key available for verification")
                                signatureStatus.color = "red"
                            }
                        } else {
                            signatureStatus.text = qsTr("⚠️ Please enter both message and signature")
                            signatureStatus.color = "orange"
                        }
                    }
                }
            }

            // Signature Output Section
            Column {
                spacing: 12
                width: parent.width
                topPadding: 10

                Label {
                    text: qsTr("🔏 Signature (ML-DSA-65):")
                    font.bold: true
                }

                TextArea {
                    id: signatureOutput
                    width: parent.width
                    height: 100
                    placeholderText: qsTr("Signature will appear here...")
                    readOnly: true
                    wrapMode: TextArea.Wrap
                    selectByMouse: true
                    leftPadding: 12
                    rightPadding: 12
                    topPadding: 10
                    bottomPadding: 10
                    background: Rectangle {
                        color: signatureOutput.text === "" ? "#f8f9fa" : "#e8f5e8"  // Light green when signature present
                        border.color: signatureOutput.text === "" ? "#dee2e6" : "#4caf50"
                        border.width: 1
                        radius: 4
                    }
                }

                Row {
                    spacing: 10
                    anchors.right: parent.right

                    Button {
                        text: qsTr("📋 Copy Signature")
                        enabled: signatureOutput.text !== ""
                        onClicked: {
                            signatureOutput.selectAll()
                            signatureOutput.copy()
                            signatureStatus.text = qsTr("📋 Signature copied to clipboard!")
                            signatureStatus.color = "blue"
                        }
                    }

                    Button {
                        text: qsTr("💾 Save Signature")
                        enabled: signatureOutput.text !== ""
                        onClicked: {
                            saveSignatureDialog.open()
                        }
                    }

                    Button {
                        text: qsTr("📂 Load Signature")
                        onClicked: {
                            loadSignatureDialog.open()
                        }
                    }

                    Button {
                        text: qsTr("🗑️ Clear")
                        onClicked: {
                            signatureOutput.text = ""
                            signatureStatus.text = ""
                        }
                    }
                }
            }

            Label {
                id: signatureStatus
                text: qsTr("ML-DSA-65 signatures provide quantum-resistant authenticity for your messages.")
                wrapMode: Text.WordWrap
                width: parent.width
                color: "#666666"
                font.pixelSize: 12
            }
        }

        // Key Management Tab
        Column {
            spacing: 20
            width: parent.width * 0.85

            Label {
                text: qsTr("🔑 Post-Quantum Key Management")
                font.pixelSize: 20
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
                width: parent.width
            }

            Label {
                text: qsTr("🛡️ 'Your keys are so quantum-safe, even Schrödinger's cat would be impressed!'")
                font.pixelSize: 12
                horizontalAlignment: Text.AlignHCenter
                width: parent.width
                color: "#666666"
                font.italic: true
            }

            Rectangle {
                width: parent.width
                height: 120
                color: "#f8f9fa"
                border.color: "#dee2e6"
                border.width: 1
                radius: 8

                Column {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 8

                    Label {
                        text: qsTr("🔐 Current Key Status:")
                        font.bold: true
                        font.pixelSize: 14
                    }

                    Label {
                        text: PostQuantumCrypto.hasKeys
                              ? qsTr("✅ PQ Key Pair Active (Kyber-1024 + ML-DSA-65)")
                              : qsTr("❌ No keys generated")
                        font.pixelSize: 12
                    }

                    Label {
                        text: qsTr("Algorithm: Kyber-1024 KEM + ML-DSA-65 Signature")
                        font.pixelSize: 11
                        color: "#666666"
                    }

                    Label {
                        text: qsTr("Security: Level 5 NIST Post-Quantum Standard")
                        font.pixelSize: 11
                        color: "#666666"
                    }
                }
            }

            // Public Key Display Section
            Column {
                spacing: 8
                width: parent.width

                Label {
                    text: qsTr("🔓 Public Key (Safe to Share):")
                    font.bold: true
                }

                TextArea {
                    id: publicKeyDisplay
                    width: parent.width
                    height: 80
                    placeholderText: qsTr("Public key will appear here...")
                    readOnly: true
                    wrapMode: TextArea.Wrap
                    selectByMouse: true
                    text: PostQuantumCrypto.hasKeys ? PostQuantumCrypto.publicKey : ""
                    background: Rectangle {
                        color: "#e8f5e8"  // Light green for public keys
                        border.color: "#4caf50"
                        border.width: 1
                        radius: 4
                    }
                }

                Row {
                    spacing: 10
                    anchors.right: parent.right

                    Button {
                        text: qsTr("📋 Copy Public Key")
                        enabled: publicKeyDisplay.text !== ""
                        onClicked: {
                            publicKeyDisplay.selectAll()
                            publicKeyDisplay.copy()
                            keyStatus.text = qsTr("📋 Public key copied to clipboard!")
                            keyStatus.color = "blue"
                        }
                    }

                    Button {
                        text: qsTr("💾 Save Public Key")
                        enabled: publicKeyDisplay.text !== ""
                        onClicked: {
                            savePublicKeyDialog.open()
                        }
                    }
                }
            }

            Row {
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter

                Button {
                    text: qsTr("🔄 Regenerate Keys")
                    onClicked: {
                        if (PostQuantumCrypto.generateKeyPair()) {
                            publicKeyDisplay.text = PostQuantumCrypto.publicKey
                            keyStatus.text = qsTr("✅ New PQ key pair generated successfully!")
                            keyStatus.color = "green"
                        } else {
                            keyStatus.text = qsTr("❌ Failed to generate key pair!")
                            keyStatus.color = "red"
                        }
                    }
                }

                Button {
                    text: qsTr("💾 Export Private Key")
                    enabled: PostQuantumCrypto.hasKeys
                    onClicked: {
                        savePrivateKeyDialog.open()
                    }
                }

                Button {
                    text: qsTr("📂 Import Key Pair")
                    onClicked: {
                        loadKeyPairDialog.open()
                    }
                }
            }

            Label {
                text: qsTr("⚠️ Security Warning: Private keys contain your secret cryptographic material. Store them securely and never share them!")
                wrapMode: Text.WordWrap
                width: parent.width
                color: "#ff9800"
                font.pixelSize: 11
                font.bold: true
            }

            Label {
                id: keyStatus
                text: qsTr("PQ keys are automatically generated from your BIP-39 mnemonic for maximum security.")
                wrapMode: Text.WordWrap
                width: parent.width
                color: "#666666"
                font.pixelSize: 12
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
