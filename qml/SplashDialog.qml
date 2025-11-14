import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import CybouWallet 1.0

Dialog {
    id: root
    title: qsTr("cybou Setup - Mnemonic & Keys Management")
    standardButtons: Dialog.NoButton
    modal: true
    closePolicy: Popup.NoAutoClose // Prevent ESC key or outside click from closing
    property alias mnemonicText: mnemonicField.text

    signal mnemonicValidated(string mnemonic)

    width: 600
    height: 500

    // Center the dialog in parent
    x: (parent.width - width) / 2
    y: (parent.height - height) / 2

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 16

        Label {
            Layout.fillWidth: true
            text: qsTr("🔐 cybou Setup\n\nGenerate or import a BIP-39 mnemonic phrase to create your post-quantum wallet. This mnemonic will derive all your cryptographic keys.")
            wrapMode: Text.WordWrap
            font.pixelSize: 14
        }

        // Mnemonic display area
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 120
            color: "#f5f5f5"
            border.color: "#cccccc"
            border.width: 1
            radius: 4

            TextArea {
                id: mnemonicField
                anchors.fill: parent
                anchors.margins: 8
                placeholderText: qsTr("Your 12-24 word mnemonic will appear here...")
                wrapMode: TextEdit.Wrap
                font.family: "Monospace"
                font.pixelSize: 13
                readOnly: false
                background: null
            }
        }

        // Status and validation feedback
        Label {
            id: statusLabel
            Layout.fillWidth: true
            text: ""
            wrapMode: Text.WordWrap
            color: "red"
            font.pixelSize: 12
        }

        // Key preview (when valid mnemonic is entered)
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 80
            color: "#e8f5e8"
            border.color: "#4caf50"
            border.width: 1
            radius: 4
            visible: mnemonicField.text.trim().length > 0 && isValidMnemonic()

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 8
                spacing: 4

                Label {
                    text: qsTr("✅ Valid Mnemonic - Derived Key Preview:")
                    font.bold: true
                    color: "#2e7d32"
                    font.pixelSize: 12
                }

                Label {
                    text: MnemonicEngine.derivedKey
                          ? qsTr("Key: %1...").arg(MnemonicEngine.derivedKey.substring(0, 32))
                          : qsTr("Key will be derived...")
                    font.family: "Monospace"
                    font.pixelSize: 11
                    color: "#2e7d32"
                    wrapMode: Text.Wrap
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Button {
                text: qsTr("🎲 Generate New Mnemonic")
                Layout.preferredWidth: 180
                onClicked: {
                    mnemonicField.text = MnemonicEngine.generateMnemonic(12)
                    statusLabel.text = ""
                }
            }

            Button {
                text: qsTr("📝 Generate 24-Word")
                Layout.preferredWidth: 140
                onClicked: {
                    mnemonicField.text = MnemonicEngine.generateMnemonic(24)
                    statusLabel.text = ""
                }
            }

            Item { Layout.fillWidth: true }

            Button {
                text: qsTr("✅ Confirm & Continue")
                Layout.preferredWidth: 150
                enabled: isValidMnemonic()
                highlighted: true
                onClicked: {
                    const text = mnemonicField.text.trim()
                    if (MnemonicEngine.setMnemonic(text)) {
                        root.mnemonicValidated(text)
                        root.close()
                    } else {
                        statusLabel.text = "Error: Failed to set mnemonic"
                    }
                }
            }
        }

        // Help text
        Label {
            Layout.fillWidth: true
            text: qsTr("💡 Tip: Write down your mnemonic phrase and store it securely. Never share it with anyone. This phrase gives access to all your encrypted data.")
            wrapMode: Text.WordWrap
            font.pixelSize: 11
            color: "#666666"
        }
    }

    function isValidMnemonic() {
        const text = mnemonicField.text.trim()
        if (text.length === 0) return false

        return MnemonicEngine.validateMnemonic(text)
    }

    onOpened: {
        // Auto-generate mnemonic on first open
        if (mnemonicField.text.trim().length === 0) {
            mnemonicField.text = MnemonicEngine.generateMnemonic(12)
        }
    }
}
