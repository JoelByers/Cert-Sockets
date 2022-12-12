#include "CertGroup.h"
//#include "CRL.h"
#include <iostream>
#include <stack>
#include <algorithm>

using namespace std;

void CertGroup::addCert(Cert487 cert){
    certs.push_back(cert);
}

bool CertGroup::validateChain(int certOneSerial, int certTwoSerial, CRL crl, bool crlValid){
    // holds the indecies of the chain from the group
    int chainStart = -1;
    if((crl.find(certOneSerial)==true||crl.find(certTwoSerial)==true)&&crlValid == true){
        cout<<"Starting or ending cert found in CRL. Connection cannot be trusted"<<endl;
        return false;
    }
    //else if(certs.)
    for(int i = 0; i < certs.size(); i++){
        if(certs.at(i).getSerialNumber() == certOneSerial){
            chainStart = i;
            if(cbcHashCheck(certs.at(i).data)==false){
                cout<<"Starting cert does not hash to signature given. Connection cannot be trusted"<<endl;
                return false;
            }
            else if((certs.at(i).data.validNotBefore>crl.checkDate()||certs.at(i).data.validNotAfter<crl.checkDate())&&crlValid==true){
                cout<<"Starting cert is outside of valid time range. Connection cannot be trusted"<<endl;
                return false;
            }
            break;
        }
    }

    // check for starting cert
    if(chainStart == -1){
        cout << "Unable to find the starting cert\n";
        return false;
    }

    return findNextLink(chainStart, certTwoSerial, crl, crlValid);
}

bool CertGroup::findNextLink(int currentIndex, int certTwoSerial, CRL crl, bool crlValid){
    if(crl.find(certs.at(currentIndex).getSerialNumber())==true && crlValid ==true){
        cout<<"Cert found in CRL connection cannot be trusted."<<endl;
        return false;
    }
    else if(cbcHashCheck(certs.at(currentIndex).data)==false){
        cout<<"Cert does not hash to the signature provided"<<endl;
        return false;
    }
    else if((certs.at(currentIndex).data.validNotBefore>crl.checkDate()||certs.at(currentIndex).data.validNotAfter<crl.checkDate())&&crlValid ==true){
        cout<<"Cert is outside of valid time range"<<endl;
        return false;
    }
    for(int i = 0; i < certs.size(); i++){        
        // check if i cert was signed by currentIndex
        // i <- currentIndex
        if(certs.at(i).getIssuer() == certs.at(currentIndex).getSubjectName()
            && certs.at(i).getSerialNumber() != certs.at(currentIndex).getSerialNumber()){
            // handle self signed certs
            // if currentIndex signed checkIndex

            cout << "Chain Verified to " << certs.at(i).getSerialNumber() << " (" << certs.at(i).getSubjectName() << ")" << endl;;

            if(certs.at(i).getSerialNumber() == certTwoSerial){
                // chain is complete
                return true;
            }
            else{
                // look for next link in the chain
                if(findNextLink(i, certTwoSerial, crl, crlValid)){
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