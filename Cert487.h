#ifndef _CERT_487_H
#define _CERT_487_H

#include <string>
using namespace std;

struct CertData{
    int version;
    int serialNumber;
    string signatureAlgorithmIdentity;
    string signatureAlgorithmParameters;
    string issuerName;
    int validNotBefore;
    int validNotAfter;
    string subjectName;
    string publicKeyAlgorithm;
    string publicKeyParameters;
    int publicKey;
    string issuerUniqueIdentifier;
    int trust;
    string extensions;
    string signatureAlgorithm;
    string signatureParameters;
    string signature;
};

class Cert487{
    private:
        // int version;
        // int serialNumber;
        // string signatureAlgorithmIdentity;
        // string signatureAlgorithmParameters;
        // string issuerName;
        // int validNotBefore;
        // int validNotAfter;
        // string subjectName;
        // string publicKeyAlgorithm;
        // string publicKeyParameters;
        // int publicKey;
        // string issuerUniqueIdentifier;
        // int trust;
        // string extensions;
        // string signatureAlgorithm;
        // string signatureParameters;
        // string signature;
        CertData data;
        void printLine(string label, string data);
        void parseCertLine(string input, string output[2]);
        void writeLineToFile(ofstream &fileOut, string label, string data);
        char cbcHash(string fileName);
        void sign(string signerFileName);
    public:
        Cert487(string fileName);
        Cert487();
        void print();
        void printLess();
        void writeToFile(string fileName);
        int getSerialNumber();
        string getIssuer();
        string getSubjectName();
        CertData getData();
};

#endif