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

    Component.onCompleted: splashDialog.open()

    FileDialog {
        id: fileDialog
        title: "Select file or folder to encrypt/decrypt"
        fileMode: FileDialog.OpenFile
        onAccepted: {
            filePath.text = fileDialog.selectedFile.toString().replace("file://", "")
        }
    }

    FileDialog {
        id: saveTextDialog
        title: "Save encrypted text as .cybou file"
        fileMode: FileDialog.SaveFile
        nameFilters: ["cybou files (*.cybou)", "All files (*)"]
        defaultSuffix: "cybou"
        onAccepted: {
            var filePath = saveTextDialog.selectedFile.toString().replace("file://", "")
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
            var filePath = loadTextDialog.selectedFile.toString().replace("file://", "")
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
            var filePath = savePublicKeyDialog.selectedFile.toString().replace("file://", "")
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

            Row {
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter

                Button {
                    text: qsTr("🔐 Encrypt File/Folder")
                    onClicked: {
                        if (filePath.text.trim() !== "") {
                            // Generate output path with .cybou extension
                            var inputPath = filePath.text
                            var outputPath = inputPath + ".cybou"

                            fileStatus.text = "Encrypting: " + inputPath + " -> " + outputPath
                            fileStatus.color = "blue"

                            if (PostQuantumCrypto.encryptFile(inputPath, outputPath)) {
                                fileStatus.text = "✅ Encryption completed: " + outputPath
                                fileStatus.color = "green"
                            } else {
                                fileStatus.text = "❌ Encryption failed!"
                                fileStatus.color = "red"
                            }
                        } else {
                            fileStatus.text = "⚠️ Please select a file first"
                            fileStatus.color = "orange"
                        }
                    }
                }

                Button {
                    text: qsTr("� Decrypt File/Folder")
                    onClicked: {
                        if (filePath.text.trim() !== "") {
                            var inputPath = filePath.text

                            // Check if it's a .cybou file
                            if (!inputPath.endsWith(".cybou")) {
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

                            if (PostQuantumCrypto.decryptFile(inputPath, outputPath)) {
                                fileStatus.text = "✅ Decryption completed: " + outputPath
                                fileStatus.color = "green"
                            } else {
                                fileStatus.text = "❌ Decryption failed!"
                                fileStatus.color = "red"
                            }
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
                        text: qsTr("� Current Key Status:")
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
                }
            }

            // Public Key Display Section
            Column {
                spacing: 8
                width: parent.width

                Label {
                    text: qsTr("🔓 Public Key:")
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
                        PostQuantumCrypto.generateKeys()
                        publicKeyDisplay.text = PostQuantumCrypto.publicKey
                        keyStatus.text = "✅ New PQ key pair generated successfully!"
                        keyStatus.color = "green"
                    }
                }

                Button {
                    text: qsTr("🔍 Show Public Key")
                    onClicked: {
                        if (PostQuantumCrypto.hasKeys) {
                            publicKeyDisplay.text = PostQuantumCrypto.publicKey
                            keyStatus.text = "🔓 Public key displayed above"
                            keyStatus.color = "blue"
                        } else {
                            keyStatus.text = "❌ No keys available"
                            keyStatus.color = "red"
                        }
                    }
                }
            }

            Label {
                id: keyStatus
                text: qsTr("PQ keys are automatically generated from your BIP-39 mnemonic.")
                wrapMode: Text.WordWrap
                width: parent.width
                color: "#666666"
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
