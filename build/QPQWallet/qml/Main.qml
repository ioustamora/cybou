import QtQuick 2.15
import QtQuick.Controls 2.15
import QPQWallet 1.0

ApplicationWindow {
    id: mainWindow
    width: 960
    height: 600
    visible: true
    title: qsTr("QPQ Encryptor - Post-Quantum File & Text Encryption")

    property bool mnemonicAccepted: false

    Component.onCompleted: splashDialog.open()

    SplashDialog {
        id: splashDialog
        modal: true
        onMnemonicValidated: function(mnemonic) {
            mnemonicAccepted = true
            mainWindow.title = qsTr("QPQ Encryptor - Ready for Encryption")
        }
    }

    header: ToolBar {
        Label {
            text: qsTr("QPQ Encryptor")
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
    Column {
        anchors.centerIn: parent
        spacing: 20
        visible: mnemonicAccepted
        width: parent.width * 0.8

        Label {
            text: qsTr("🎉 Post-Quantum Encryptor Ready!")
            font.pixelSize: 24
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            width: parent.width
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
                    text: qsTr("📝 Current Mnemonic:")
                    font.bold: true
                    font.pixelSize: 14
                }

                Label {
                    text: MnemonicEngine.currentMnemonic || "No mnemonic set"
                    font.family: "Monospace"
                    font.pixelSize: 12
                    wrapMode: Text.Wrap
                    width: parent.width
                }
            }
        }

        Rectangle {
            width: parent.width
            height: 100
            color: "#e8f5e8"
            border.color: "#4caf50"
            border.width: 1
            radius: 8

            Column {
                anchors.fill: parent
                anchors.margins: 16
                spacing: 8

                Label {
                    text: qsTr("🔑 Derived Master Key:")
                    font.bold: true
                    font.pixelSize: 14
                    color: "#2e7d32"
                }

                Label {
                    text: MnemonicEngine.derivedKey || "Key derivation in progress..."
                    font.family: "Monospace"
                    font.pixelSize: 11
                    color: "#2e7d32"
                    wrapMode: Text.Wrap
                    width: parent.width
                }
            }
        }

        Rectangle {
            width: parent.width
            height: 100
            color: "#fff3e0"
            border.color: "#ff9800"
            border.width: 1
            radius: 8

            Column {
                anchors.fill: parent
                anchors.margins: 16
                spacing: 8

                Label {
                    text: qsTr("🔐 Post-Quantum Key Pair (Kyber-1024 + Dilithium):")
                    font.bold: true
                    font.pixelSize: 14
                    color: "#e65100"
                }

                Label {
                    text: PostQuantumCrypto.hasKeys
                          ? qsTr("Public Key: %1...").arg(PostQuantumCrypto.publicKey.substring(0, 32))
                          : "PQ keys will be generated..."
                    font.family: "Monospace"
                    font.pixelSize: 11
                    color: "#e65100"
                    wrapMode: Text.Wrap
                    width: parent.width
                }
            }
        }

        Label {
            text: qsTr("🚀 Post-Quantum Encryption Ready!\n\nFeatures: Kyber-1024 key encapsulation, CRYSTALS-Dilithium signatures, secure file/folder encryption")
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
            width: parent.width
            font.pixelSize: 14
            color: "#666666"
        }
    }

    // Setup required message - shown before mnemonic is set
    Column {
        anchors.centerIn: parent
        spacing: 16
        visible: !mnemonicAccepted

        Label {
            text: qsTr("🔐 Post-Quantum Encryptor Setup Required")
            font.pixelSize: 20
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            width: parent.width * 0.8
        }

        Label {
            text: qsTr("Please complete the mnemonic setup in the dialog that appeared.\n\nYour post-quantum encryptor will be ready for secure file and text encryption operations.")
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
            width: parent.width * 0.8
            color: "#666666"
        }
    }
}
