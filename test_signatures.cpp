#include <QCoreApplication>
#include <QDebug>
#include <oqs/oqs.h>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    qDebug() << "OQS Kyber-1024 public key length:" << OQS_KEM_kyber_1024_length_public_key;
    qDebug() << "OQS ML-DSA-65 public key length:" << OQS_SIG_ml_dsa_65_length_public_key;
    qDebug() << "OQS ML-DSA-65 signature length:" << OQS_SIG_ml_dsa_65_length_signature;
    qDebug() << "Expected combined public key length:" << (OQS_KEM_kyber_1024_length_public_key + OQS_SIG_ml_dsa_65_length_public_key);
    
    return 0;
}
