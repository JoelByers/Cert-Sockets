#include "CertGroup.h"
#include <iostream>
#include <stack>
#include <algorithm>

using namespace std;

void CertGroup::addCert(Cert487 cert){
    certs.push_back(cert);
}

bool CertGroup::validateChain(int certOneSerial, int certTwoSerial){
    // holds the indecies of the chain from the group
    int chainStart = -1;

    // find starting cert
    for(int i = 0; i < certs.size(); i++){
        if(certs.at(i).getSerialNumber() == certOneSerial){
            chainStart = i;
            break;
        }
    }

    // check for starting cert
    if(chainStart == -1){
        cout << "Unable to find the starting cert\n";
        return false;
    }

    return findNextLink(chainStart, certTwoSerial);
}

bool CertGroup::findNextLink(int currentIndex, int certTwoSerial){
    for(int i = 0; i < certs.size(); i++){        
        // check if i cert was signed by currentIndex
        // i <- currentIndex
        //cerr << "c: " << currentIndex << " i: " << i << endl;
        if(certs.at(i).getIssuer() == certs.at(currentIndex).getSubjectName()
            && certs.at(i).getSerialNumber() != certs.at(currentIndex).getSerialNumber()){
            // handle self signed certs
            // if currentIndex signed checkIndex
            if(certs.at(i).getSerialNumber() == certTwoSerial){
                // chain is complete
                return true;
            }
            else{
                // look for next link in the chain
                if(findNextLink(i, certTwoSerial)){
                    return true;
                }
            }
        }

        //check for self signed certs
        if(certs.at(i).getSerialNumber() == certs.at(currentIndex).getSerialNumber()
            && certs.at(i).getSerialNumber() == certTwoSerial){
            
            return true;
        }
    }

    return false;
}

void CertGroup::print(){
    for(int i = 0; i < certs.size(); i++){
        certs.at(i).printLess();
        cout << endl;
    }
}