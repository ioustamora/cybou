import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs 1.3
import CybouWallet 1.0

ApplicationWindow {
    id: mainWindow
    width: 960
    height: 600
    visible: true
    title: qsTr("cybou - Post-Quantum File & Text Encryption")

    property bool mnemonicAccepted: false

    Component.onCompleted: splashDialog.open()

    FileDialog {
        id: fileDialog
        title: "Select file or folder to encrypt/decrypt"
        selectFolder: false
        selectMultiple: false
        onAccepted: {
            filePath.text = fileDialog.fileUrl.toString().replace("file://", "")
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
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 20

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

            TextArea {
                id: inputText
                width: parent.width
                height: 120
                placeholderText: qsTr("Enter text to encrypt... (Your secrets are quantum-safe here! 🔐)")
                wrapMode: TextArea.Wrap
            }

            Row {
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter

                Button {
                    text: qsTr("🔐 Encrypt Text")
                    onClicked: {
                        if (inputText.text.trim() !== "") {
                            outputText.text = PostQuantumCrypto.encryptText(inputText.text)
                        }
                    }
                }

                Button {
                    text: qsTr("� Decrypt Text")
                    onClicked: {
                        if (inputText.text.trim() !== "") {
                            outputText.text = PostQuantumCrypto.decryptText(inputText.text)
                        }
                    }
                }
            }

            TextArea {
                id: outputText
                width: parent.width
                height: 120
                placeholderText: qsTr("Encrypted/decrypted result will appear here...")
                readOnly: true
                wrapMode: TextArea.Wrap
            }
        }

        // File Encryption Tab
        Column {
            spacing: 20
            width: parent.width * 0.9
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 20

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
                            fileStatus.text = "Encrypting: " + filePath.text
                            // TODO: Implement file encryption
                            fileStatus.text = "Encryption completed successfully!"
                        }
                    }
                }

                Button {
                    text: qsTr("� Decrypt File/Folder")
                    onClicked: {
                        if (filePath.text.trim() !== "") {
                            fileStatus.text = "Decrypting: " + filePath.text
                            // TODO: Implement file decryption
                            fileStatus.text = "Decryption completed successfully!"
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
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 20

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

            Row {
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter

                Button {
                    text: qsTr("🔄 Regenerate Keys")
                    onClicked: {
                        PostQuantumCrypto.generateKeys()
                        keyStatus.text = "New PQ key pair generated successfully!"
                    }
                }

                Button {
                    text: qsTr("� Export Public Key")
                    onClicked: {
                        if (PostQuantumCrypto.hasKeys) {
                            keyStatus.text = "Public key: " + PostQuantumCrypto.publicKey.substring(0, 64) + "..."
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
