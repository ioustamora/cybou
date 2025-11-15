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
        Label {
            text: qsTr("cybou")
            anchors.verticalCenter: parent.verticalCenter
            font.bold: true
            leftPadding: 12
        }

        Row {
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 8

            Label {
                text: mnemonicAccepted ? qsTr("🔐 PQ Keys Active") : qsTr("🔓 Setup Required")
                color: mnemonicAccepted ? "green" : "orange"
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
            width: parent.width * 0.9
            Layout.alignment: Qt.AlignHCenter | Qt.AlignTop
            Layout.topMargin: 20

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
                spacing: 8
                width: parent.width

                Label {
                    text: qsTr("📝 Input Text:")
                    font.bold: true
                }

                TextArea {
                    id: inputText
                    width: parent.width
                    height: 100
                    placeholderText: qsTr("Enter text to encrypt... (Your secrets are quantum-safe here! 🔐)")
                    wrapMode: TextArea.Wrap
                    background: Rectangle {
                        color: "#e8f4fd"  // Light blue background for input
                        border.color: "#4a90e2"
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
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter

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
                spacing: 8
                width: parent.width

                Label {
                    text: qsTr("📄 Output Text:")
                    font.bold: true
                }

                TextArea {
                    id: outputText
                    width: parent.width
                    height: 100
                    placeholderText: qsTr("Encrypted/decrypted result will appear here...")
                    readOnly: true
                    wrapMode: TextArea.Wrap
                    selectByMouse: true
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
                    spacing: 10
                    anchors.right: parent.right

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
            }
        }

        // File Encryption Tab
        Column {
            spacing: 20
            width: parent.width * 0.9
            Layout.alignment: Qt.AlignHCenter | Qt.AlignTop
            Layout.topMargin: 20

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

            Row {
                spacing: 10
                width: parent.width

                TextField {
                    id: filePath
                    width: parent.width - 120
                    placeholderText: qsTr("Select file or folder path...")
                    readOnly: true
                }

                Button {
                    text: qsTr("📂 Browse")
                    width: 100
                    onClicked: {
                        fileDialog.open()
                    }
                }
            }

            // Progress Bar for file operations
            Column {
                spacing: 8
                width: parent.width
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
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter

                Button {
                    id: encryptButton
                    text: qsTr("🔐 Encrypt File/Folder")
                    enabled: !fileProgressBar.visible
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
                            fileStatus.color = "blue"

                            var success = PostQuantumCrypto.encryptFile(inputPath, outputPath)
                            if (success) {
                                fileStatus.text = "✅ Encryption completed: " + outputPath
                                fileStatus.color = "green"
                            } else {
                                fileStatus.text = "❌ Encryption failed!"
                                fileStatus.color = "red"
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
                    id: decryptButton
                    text: qsTr("🔓 Decrypt File/Folder")
                    enabled: !fileProgressBar.visible
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
                                fileStatus.text = "⚠️ Selected file is not a .cybou encrypted file"
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
                            fileStatus.color = "blue"

                            var success = PostQuantumCrypto.decryptFile(inputPath, outputPath)
                            if (success) {
                                fileStatus.text = "✅ Decryption completed: " + outputPath
                                fileStatus.color = "green"
                            } else {
                                fileStatus.text = "❌ Decryption failed!"
                                fileStatus.color = "red"
                            }

                            fileProgressBar.visible = false
                            progressStatus.text = ""
                        } else {
                            fileStatus.text = "⚠️ Please select a .cybou file first"
                            fileStatus.color = "orange"
                        }
                    }
                }
            }

            Label {
                id: fileStatus
                text: qsTr("Select a file or folder to begin encryption/decryption operations.")
                wrapMode: Text.WordWrap
                width: parent.width
                color: "#666666"
            }
        }

        // Digital Signatures Tab
        Column {
            spacing: 20
            width: parent.width * 0.9
            Layout.alignment: Qt.AlignHCenter | Qt.AlignTop
            Layout.topMargin: 20

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
                spacing: 8
                width: parent.width

                Label {
                    text: qsTr("📝 Message to Sign:")
                    font.bold: true
                }

                TextArea {
                    id: signMessageText
                    width: parent.width
                    height: 100
                    placeholderText: qsTr("Enter message to sign with ML-DSA-65...")
                    wrapMode: TextArea.Wrap
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
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter

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
                spacing: 8
                width: parent.width

                Label {
                    text: qsTr("🔏 Signature (ML-DSA-65):")
                    font.bold: true
                }

                TextArea {
                    id: signatureOutput
                    width: parent.width
                    height: 80
                    placeholderText: qsTr("Signature will appear here...")
                    readOnly: true
                    wrapMode: TextArea.Wrap
                    selectByMouse: true
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
            width: parent.width * 0.9
            Layout.alignment: Qt.AlignHCenter | Qt.AlignTop
            Layout.topMargin: 20

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
