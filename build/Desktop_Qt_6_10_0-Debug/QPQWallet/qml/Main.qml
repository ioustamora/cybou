import QtQuick 2.15
import QtQuick.Controls 2.15

ApplicationWindow {
    id: mainWindow
    width: 960
    height: 600
    visible: true
    title: qsTr("Post-Quantum Crypto Toolkit")

    property bool mnemonicAccepted: false

    Component.onCompleted: splashDialog.open()

    SplashDialog {
        id: splashDialog
        modality: Qt.ApplicationModal
        onMnemonicValidated: function(mnemonic) {
            mnemonicAccepted = true
            // TODO: pass mnemonic to C++ backend for key derivation
        }
    }

    header: ToolBar {
        Label {
            text: qsTr("QPQ Toolkit")
            anchors.verticalCenter: parent.verticalCenter
            font.bold: true
            leftPadding: 12
        }
    }

    Column {
        anchors.centerIn: parent
        spacing: 16

        Label {
            text: mnemonicAccepted
                  ? qsTr("Mnemonic is set. Future: derive PQ KEM/ML-DSA keys.")
                  : qsTr("Please enter or generate a mnemonic in the splash dialog.")
            wrapMode: Text.WordWrap
            width: parent.width * 0.8
            horizontalAlignment: Text.AlignHCenter
        }

        Button {
            text: qsTr("Show Splash / Mnemonic Setup")
            onClicked: splashDialog.open()
        }
    }
}
