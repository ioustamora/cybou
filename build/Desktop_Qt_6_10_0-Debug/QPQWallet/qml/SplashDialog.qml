import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root
    title: qsTr("Mnemonic Setup")
    standardButtons: Dialog.NoButton
    modal: true
    property alias mnemonicText: mnemonicField.text

    signal mnemonicValidated(string mnemonic)

    width: 520

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: qsTr("Generate a new mnemonic or paste an existing one. This will later derive post-quantum keys (Kyber-like KEM + AEAD, ML-DSA/SLH-DSA-like signatures).")
            wrapMode: Text.WordWrap
        }

        TextArea {
            id: mnemonicField
            Layout.fillWidth: true
            Layout.fillHeight: true
            placeholderText: qsTr("example: legal winner thank year wave sausage worth useful legal winner thank yellow")
            wrapMode: TextEdit.Wrap
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            Button {
                text: qsTr("Generate")
                onClicked: {
                    if (typeof mnemonicEngine !== "undefined") {
                        mnemonicField.text = mnemonicEngine.generateMnemonic(12)
                    } else {
                        // Fallback demo text
                        mnemonicField.text = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
                    }
                }
            }

            Item { Layout.fillWidth: true }

            Button {
                text: qsTr("Cancel")
                onClicked: root.close()
            }

            Button {
                text: qsTr("Continue")
                enabled: mnemonicField.text.trim().length > 0
                onClicked: {
                    const text = mnemonicField.text.trim()
                    if (typeof mnemonicEngine !== "undefined") {
                        if (!mnemonicEngine.validateMnemonic(text)) {
                            // Very simple inline error; later we can use proper error labels.
                            console.warn("Mnemonic failed basic validation")
                            return
                        }
                    }
                    root.mnemonicValidated(text)
                    root.close()
                }
            }
        }
    }
}
