#ifndef _CRL_H
#define _CRL_H

#include <string>
#include <list>
#include "Cert487.h"

using namespace std;

struct crlobject{
    string signatureAlgorithmIdentity = "cbc";
    string signatureAlgorithmParameters = "none";
    string issuerName = "CertificateAuthority";
    int thisDate = 2;
    int nextDate=4;
    int revokedSerialNumber;
    int revokedDate=2;
};

class CRL{
    private:
        list<crlobject> crlList;
        char cbcHash(string fileName);
        bool cbcHashCheck(string fileName);
    public:
        CRL(string fileName);
        void printCRL(string fileName);
};

#endif