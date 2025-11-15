import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

/**
 * KeyManagementTab.qml
 * Reusable component for key generation, import, and export
 * Handles all key management operations
 */
Item {
    id: root
    
    // Public properties
    property bool darkMode: false
    property bool hasKeys: false
    
    // Signals
    signal keysGenerated()
    signal keysImported()
    signal keyExported(string keyType, string keyData)
    
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 15
        
        // Title
        Label {
            text: "Key Management"
            font.pixelSize: 18
            font.bold: true
            color: darkMode ? "#E0E0E0" : "#333333"
        }
        
        // Generate Keys Section
        GroupBox {
            Layout.fillWidth: true
            title: "Generate New Keys"
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 12
                
                Label {
                    text: "Generate a new quantum-resistant key pair (Kyber-1024 + ML-DSA-65)"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                Button {
                    text: "Generate Key Pair"
                    Layout.preferredWidth: 200
                    onClicked: {
                        if (PostQuantumCrypto.generateKeyPair()) {
                            hasKeys = true
                            publicKeyDisplay.text = PostQuantumCrypto.exportPublicKey()
                            keysGenerated()
                        }
                    }
                    background: Rectangle {
                        color: parent.pressed ? "#0056b3" : "#007BFF"
                        radius: 4
                    }
                    contentItem: Text {
                        text: parent.text
                        color: "#FFFFFF"
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                }
                
                Label {
                    text: "Current Public Key:"
                    color: darkMode ? "#E0E0E0" : "#333333"
                    visible: hasKeys
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 100
                    visible: hasKeys
                    
                    TextArea {
                        id: publicKeyDisplay
                        readOnly: true
                        wrapMode: TextArea.Wrap
                        font.family: "Courier New"
                        font.pixelSize: 10
                        background: Rectangle {
                            color: darkMode ? "#1E1E1E" : "#F5F5F5"
                            border.color: darkMode ? "#555555" : "#CCCCCC"
                            border.width: 1
                            radius: 4
                        }
                        color: darkMode ? "#E0E0E0" : "#000000"
                        padding: 10
                    }
                }
                
                RowLayout {
                    spacing: 10
                    visible: hasKeys
                    
                    Button {
                        text: "Copy Public Key"
                        onClicked: {
                            publicKeyDisplay.selectAll()
                            publicKeyDisplay.copy()
                            publicKeyDisplay.deselect()
                        }
                        background: Rectangle {
                            color: parent.pressed ? "#138496" : "#17A2B8"
                            radius: 4
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "#FFFFFF"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
            }
        }
        
        // Export Keys Section
        GroupBox {
            Layout.fillWidth: true
            title: "Export Keys"
            visible: hasKeys
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 12
                
                Label {
                    text: "Export your private key for backup. Keep it secure!"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    color: darkMode ? "#E0E0E0" : "#333333"
                    font.bold: true
                }
                
                RowLayout {
                    spacing: 10
                    
                    Button {
                        text: "Export Private Key"
                        onClicked: {
                            privateKeyExportArea.text = PostQuantumCrypto.exportPrivateKey()
                            keyExported("private", privateKeyExportArea.text)
                        }
                        background: Rectangle {
                            color: parent.pressed ? "#c82333" : "#DC3545"
                            radius: 4
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "#FFFFFF"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    
                    Button {
                        text: "Export Public Key"
                        onClicked: {
                            privateKeyExportArea.text = PostQuantumCrypto.exportPublicKey()
                            keyExported("public", privateKeyExportArea.text)
                        }
                        background: Rectangle {
                            color: parent.pressed ? "#138496" : "#17A2B8"
                            radius: 4
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "#FFFFFF"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    
                    TextArea {
                        id: privateKeyExportArea
                        readOnly: true
                        wrapMode: TextArea.Wrap
                        font.family: "Courier New"
                        font.pixelSize: 10
                        placeholderText: "Exported key will appear here..."
                        background: Rectangle {
                            color: darkMode ? "#1E1E1E" : "#F5F5F5"
                            border.color: darkMode ? "#555555" : "#CCCCCC"
                            border.width: 1
                            radius: 4
                        }
                        color: darkMode ? "#E0E0E0" : "#000000"
                        padding: 10
                    }
                }
                
                Button {
                    text: "Copy Exported Key"
                    enabled: privateKeyExportArea.text.length > 0
                    onClicked: {
                        privateKeyExportArea.selectAll()
                        privateKeyExportArea.copy()
                        privateKeyExportArea.deselect()
                    }
                    background: Rectangle {
                        color: parent.enabled ? (parent.pressed ? "#138496" : "#17A2B8") : "#6C757D"
                        radius: 4
                    }
                    contentItem: Text {
                        text: parent.text
                        color: "#FFFFFF"
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                }
            }
        }
        
        // Import Keys Section
        GroupBox {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: "Import Keys"
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 12
                
                Label {
                    text: "Import previously exported keys"
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                Label {
                    text: "Private Key (Hex):"
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 80
                    
                    TextArea {
                        id: importPrivateKeyArea
                        placeholderText: "Paste private key here..."
                        wrapMode: TextArea.Wrap
                        font.family: "Courier New"
                        font.pixelSize: 10
                        background: Rectangle {
                            color: darkMode ? "#2C2C2C" : "#FFFFFF"
                            border.color: darkMode ? "#555555" : "#CCCCCC"
                            border.width: 1
                            radius: 4
                        }
                        color: darkMode ? "#E0E0E0" : "#000000"
                        padding: 10
                    }
                }
                
                Label {
                    text: "Public Key (Hex):"
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 80
                    
                    TextArea {
                        id: importPublicKeyArea
                        placeholderText: "Paste public key here..."
                        wrapMode: TextArea.Wrap
                        font.family: "Courier New"
                        font.pixelSize: 10
                        background: Rectangle {
                            color: darkMode ? "#2C2C2C" : "#FFFFFF"
                            border.color: darkMode ? "#555555" : "#CCCCCC"
                            border.width: 1
                            radius: 4
                        }
                        color: darkMode ? "#E0E0E0" : "#000000"
                        padding: 10
                    }
                }
                
                RowLayout {
                    spacing: 10
                    
                    Button {
                        text: "Import Key Pair"
                        enabled: importPrivateKeyArea.text.length > 0 && 
                                importPublicKeyArea.text.length > 0
                        onClicked: {
                            if (PostQuantumCrypto.importKeyPair(
                                importPrivateKeyArea.text,
                                importPublicKeyArea.text
                            )) {
                                hasKeys = true
                                publicKeyDisplay.text = PostQuantumCrypto.exportPublicKey()
                                importPrivateKeyArea.clear()
                                importPublicKeyArea.clear()
                                keysImported()
                            }
                        }
                        background: Rectangle {
                            color: parent.enabled ? (parent.pressed ? "#218838" : "#28A745") : "#6C757D"
                            radius: 4
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "#FFFFFF"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    
                    Button {
                        text: "Clear"
                        onClicked: {
                            importPrivateKeyArea.clear()
                            importPublicKeyArea.clear()
                        }
                        background: Rectangle {
                            color: parent.pressed ? "#5A6268" : "#6C757D"
                            radius: 4
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "#FFFFFF"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
                
                Item { Layout.fillHeight: true }
            }
        }
    }
}
