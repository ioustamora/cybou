import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

/**
 * SignatureTab.qml
 * Reusable component for digital signature operations
 * Handles message signing and signature verification
 */
Item {
    id: root
    
    // Public properties
    property bool darkMode: false
    property string lastSignatureOperation: ""
    
    // Signals
    signal signatureCreated(string signature)
    signal signatureVerified(bool isValid)
    signal saveSignatureRequested(string signature)
    signal loadSignatureRequested()
    
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 15
        
        // Title
        Label {
            text: "Digital Signatures"
            font.pixelSize: 18
            font.bold: true
            color: darkMode ? "#E0E0E0" : "#333333"
        }
        
        // Sign Message Section
        GroupBox {
            Layout.fillWidth: true
            Layout.preferredHeight: 280
            title: "Sign Message"
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 12
                
                Label {
                    text: "Message to Sign:"
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    
                    TextArea {
                        id: messageToSignArea
                        placeholderText: "Enter message to sign..."
                        wrapMode: TextArea.Wrap
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
                        text: "Sign Message"
                        enabled: messageToSignArea.text.length > 0
                        onClicked: {
                            if (messageToSignArea.text.length > 0) {
                                var signature = PostQuantumCrypto.signMessage(messageToSignArea.text)
                                if (signature) {
                                    signatureOutputArea.text = signature
                                    lastSignatureOperation = "signed"
                                    signatureCreated(signature)
                                }
                            }
                        }
                        background: Rectangle {
                            color: parent.enabled ? (parent.pressed ? "#0056b3" : "#007BFF") : "#6C757D"
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
                            messageToSignArea.clear()
                            signatureOutputArea.clear()
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
                
                Label {
                    text: "Signature:"
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    
                    TextArea {
                        id: signatureOutputArea
                        readOnly: true
                        wrapMode: TextArea.Wrap
                        placeholderText: "Signature will appear here..."
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
                    
                    Button {
                        text: "Copy Signature"
                        enabled: signatureOutputArea.text.length > 0
                        onClicked: {
                            signatureOutputArea.selectAll()
                            signatureOutputArea.copy()
                            signatureOutputArea.deselect()
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
                    
                    Button {
                        text: "Save Signature"
                        enabled: signatureOutputArea.text.length > 0
                        onClicked: {
                            saveSignatureRequested(signatureOutputArea.text)
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
                }
            }
        }
        
        // Verify Signature Section
        GroupBox {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: "Verify Signature"
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 12
                
                Label {
                    text: "Message:"
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 80
                    
                    TextArea {
                        id: messageToVerifyArea
                        placeholderText: "Enter original message..."
                        wrapMode: TextArea.Wrap
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
                    text: "Signature to Verify:"
                    color: darkMode ? "#E0E0E0" : "#333333"
                }
                
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 80
                    
                    TextArea {
                        id: signatureToVerifyArea
                        placeholderText: "Paste signature here..."
                        wrapMode: TextArea.Wrap
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
                
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 10
                    
                    TextField {
                        id: publicKeyField
                        Layout.fillWidth: true
                        placeholderText: "Enter or use current public key..."
                        background: Rectangle {
                            color: darkMode ? "#2C2C2C" : "#FFFFFF"
                            border.color: darkMode ? "#555555" : "#CCCCCC"
                            border.width: 1
                            radius: 4
                        }
                        color: darkMode ? "#E0E0E0" : "#000000"
                        padding: 8
                    }
                    
                    Button {
                        text: "Use My Key"
                        onClicked: {
                            publicKeyField.text = PostQuantumCrypto.exportPublicKey()
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
                
                RowLayout {
                    spacing: 10
                    
                    Button {
                        text: "Verify Signature"
                        enabled: messageToVerifyArea.text.length > 0 && 
                                signatureToVerifyArea.text.length > 0 && 
                                publicKeyField.text.length > 0
                        onClicked: {
                            var isValid = PostQuantumCrypto.verifySignature(
                                messageToVerifyArea.text,
                                signatureToVerifyArea.text,
                                publicKeyField.text
                            )
                            verificationResultLabel.text = isValid ? 
                                "✓ Signature Valid" : "✗ Signature Invalid"
                            verificationResultLabel.color = isValid ? "#28A745" : "#DC3545"
                            lastSignatureOperation = "verified"
                            signatureVerified(isValid)
                        }
                        background: Rectangle {
                            color: parent.enabled ? (parent.pressed ? "#0056b3" : "#007BFF") : "#6C757D"
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
                        text: "Clear All"
                        onClicked: {
                            messageToVerifyArea.clear()
                            signatureToVerifyArea.clear()
                            publicKeyField.clear()
                            verificationResultLabel.text = ""
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
                
                Label {
                    id: verificationResultLabel
                    text: ""
                    font.pixelSize: 14
                    font.bold: true
                }
                
                Item { Layout.fillHeight: true }
            }
        }
    }
}
