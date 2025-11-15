/**
 * @file TextEncryptionTab.qml
 * @brief Text encryption/decryption interface component
 *
 * Provides UI for:
 * - Text input with paste/clear functions
 * - Encrypt/decrypt operations
 * - Output display with copy/save functions
 * - Status messaging
 */

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Dialogs
import CybouWallet 1.0

/**
 * @component TextEncryptionTab
 * @brief Tab for encrypting and decrypting text
 *
 * Features:
 * - Multi-line text input with visual feedback
 * - One-click encryption/decryption buttons
 * - Color-coded output (green=encrypted, red=decrypted)
 * - Copy/paste/clear/save functionality
 * - Status messages with operation results
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

    // Properties for parent access
    property bool darkMode: false
    property string lastTextOperation: ""

    // Signal for file dialog operations
    signal saveTextRequested(string content)
    signal loadTextRequested()

    // Title Section
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
                color: "#e8f4fd"
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

    // Encrypt/Decrypt Buttons
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
                        root.lastTextOperation = "encrypt"
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
                        root.lastTextOperation = "decrypt"
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
                color: outputText.text === "" ? "#f8f9fa" :
                       (root.lastTextOperation === "encrypt" ? "#e8f5e8" :
                       (root.lastTextOperation === "decrypt" ? "#fce8e6" : "#f8f9fa"))
                border.color: outputText.text === "" ? "#dee2e6" :
                             (root.lastTextOperation === "encrypt" ? "#4caf50" :
                             (root.lastTextOperation === "decrypt" ? "#f44336" : "#dee2e6"))
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
                    root.saveTextRequested(outputText.text)
                }
            }

            Button {
                text: qsTr("📂 Load .cybou")
                onClicked: {
                    root.loadTextRequested()
                }
            }

            Button {
                text: qsTr("🗑️ Clear")
                onClicked: {
                    outputText.text = ""
                    root.lastTextOperation = ""
                    textStatus.text = ""
                }
            }
        }
    }

    // Status Label
    Label {
        id: textStatus
        text: ""
        wrapMode: Text.WordWrap
        width: parent.width
        font.pixelSize: 12
        topPadding: 10
    }

    // Function to load text from external source
    function loadText(content) {
        inputText.text = content
        textStatus.text = qsTr("📂 File loaded successfully")
        textStatus.color = "blue"
    }
}
