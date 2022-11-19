#ifndef _CERT_GROUP_H
#define _CERT_GROUP_H

#include <vector>
#include <stack>
#include "Cert487.h"

class CertGroup {
    private:
        vector<Cert487> certs;
        bool findNextLink(int currentIndex, int certTwoSerial);
    public:
        void addCert(Cert487 cert);
        bool validateChain(int certOneSerial, int certTwoSerial);
        void print();

};

#endif