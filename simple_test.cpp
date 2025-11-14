/**
 * @file simple_test.cpp
 * @brief Simple test program for cryptographic primitives
 *
 * This file contains basic tests for the deterministic key generation
 * and XOR encryption/decryption logic used in the post-quantum crypto
 * implementation. It validates that:
 * - Deterministic key generation produces consistent results
 * - XOR encryption/decryption is reversible
 * - Basic cryptographic building blocks work correctly
 *
 * This is a standalone test program that can be run independently
 * of the main Qt application.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <QCryptographicHash>
#include <QByteArray>
#include <QString>

// Simple test of the deterministic key generation logic
QByteArray generateDeterministicKey(const uint8_t* kyberKey, const uint8_t* dilithiumKey) {
    QByteArray keyMaterial;

    // Simulate key data (32 bytes each for demo)
    keyMaterial.append(reinterpret_cast<const char*>(kyberKey), 32);
    keyMaterial.append(reinterpret_cast<const char*>(dilithiumKey), 32);
    keyMaterial.append("cybou_pq_key_derivation_salt_2024");

    QByteArray hash = QCryptographicHash::hash(keyMaterial, QCryptographicHash::Sha256);
    return hash;
}

void testXOR(const std::string& plaintext, const QByteArray& key) {
    std::string ciphertext = plaintext;
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        ciphertext[i] = ciphertext[i] ^ key[i % key.size()];
    }

    std::string decrypted = ciphertext;
    for (size_t i = 0; i < decrypted.size(); ++i) {
        decrypted[i] = decrypted[i] ^ key[i % key.size()];
    }

    std::cout << "Original:  " << plaintext << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << "Match: " << (plaintext == decrypted ? "YES" : "NO") << std::endl;
}

int main() {
    // Test deterministic key generation
    uint8_t kyberKey[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t dilithiumKey[32] = {32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};

    QByteArray key1 = generateDeterministicKey(kyberKey, dilithiumKey);
    QByteArray key2 = generateDeterministicKey(kyberKey, dilithiumKey);

    std::cout << "Key1 == Key2: " << (key1 == key2 ? "YES" : "NO") << std::endl;
    std::cout << "Key length: " << key1.size() << std::endl;

    // Test XOR encryption/decryption
    testXOR("Hello, quantum world!", key1);

    return 0;
}
