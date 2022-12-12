#include <iostream>
#include <string>
#include <fstream>
#include <cstring>
#include "CRL.h"
#include "RSA.h"
#include "SDES.h"
#include "Cert487.h"

using namespace std;

void parseLine(string input, string output[2]){
    output[0] = input.substr(0, input.find("="));
    output[1] = input.substr(input.find("=") + 1, input.length() - 1);
}

CRL::CRL(string fileName){
    crlobject tempcrlobject;
    ifstream crlFile;
    crlFile.open(fileName);
    ofstream outfile;
    //outfile.open("CRLout.txt");
    string temp;
    string parsedInput[2] = {"",""};
    while(!crlFile.eof()){
        getline(crlFile, temp);
        parseLine(temp, parsedInput);
        if(parsedInput[0].compare("Signature Algorithm Identity")==0){
            strcpy(tempcrlobject.signatureAlgorithmIdentity, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("Signature Algorithm Parameters")==0){
            strcpy(tempcrlobject.signatureAlgorithmParameters, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("Issuer Name")==0){
            strcpy(tempcrlobject.issuerName, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("This Date")==0){
            tempcrlobject.thisDate = stoi(parsedInput[1]);
        }
        else if(parsedInput[0].compare("Next Date")==0){
            tempcrlobject.nextDate = stoi(parsedInput[1]);
        }
        else if(parsedInput[0].compare("Revoked Serial Number")==0){
            tempcrlobject.revokedSerialNumber = stoi(parsedInput[1]);
        }
        else if(parsedInput[0].compare("Revoked Date")==0){
            tempcrlobject.revokedDate = stoi(parsedInput[1]);
            crlList.push_back(tempcrlobject);
        }
        else if(parsedInput[0].compare("signature")==0){
            //cout<<parsedInput[1][0]<<endl;
            signature = parsedInput[1][0];
        }
    }
    //signature = getSignature();
    //outfile<<"signature="<<cbcHash(fileName);
    //outfile.close();
}

CRL::CRL(){}



void CRL::printCRL(){
    // ifstream crlFile;
    // crlFile.open(fileName);
    ofstream outfile;
    outfile.open("crl.txt");
    string temp;
    for(crlobject obj : crlList){
        writeLineToFile(outfile, "Signature Algorithm Identity", obj.signatureAlgorithmIdentity);
        writeLineToFile(outfile, "Signature Algorithm Parameters", obj.signatureAlgorithmParameters);
        writeLineToFile(outfile, "Issuer Name", obj.issuerName);
        writeLineToFile(outfile, "This Date", to_string(obj.thisDate));
        writeLineToFile(outfile, "Revoked Serial Number", to_string(obj.revokedSerialNumber));
        writeLineToFile(outfile, "Revoked Date", to_string(obj.revokedDate));
    }
    string sign(1,cbcHash());
    writeLineToFile(outfile, "signature", sign);
    outfile.close();
}
void CRL::writeLineToFile(ofstream &fileOut, string label, string data){
    fileOut << label << "=" << data << "\n";
}
void CRL::print(){
    for(crlobject obj : crlList){
        cout << "Signature Algorithm Identity: " << obj.signatureAlgorithmIdentity << endl;
        cout << "Signature Algorithm Parameters: " << obj.signatureAlgorithmParameters << endl;
        cout << "Issuer Name: " << obj.issuerName << endl;
        cout << "This Date: " << obj.thisDate << endl;
        cout << "Next Date: " << obj.nextDate << endl;
        cout << "Revoked Serial Number: " << obj.revokedSerialNumber << endl;
        cout << "Revoked Date: " << obj.revokedDate << endl << endl;
    }
    
}

int CRL::checkDate(){
    if(crlList.size()>0){
        return crlList.front().thisDate;
    }
    return 0;
}

bool CRL::cbcHashCheck(){
	// fstream infile(fileName);
	string temp;
    for(crlobject obj : crlList){
        temp += "Signature Algorithm Identity: " + string(obj.signatureAlgorithmIdentity) + "Signature Algorithm Parameters: "+string(obj.signatureAlgorithmParameters)+
                "Issuer Name: " + string(obj.issuerName) + "This Date: "+to_string(obj.thisDate) + "Next Date: " + to_string(obj.nextDate) + "Revoked Serial Number: "+to_string(obj.revokedSerialNumber)+
                "Revoked Date: " + to_string(obj.revokedDate);
    }
    // string temp1;
    // string tempSerialString;
    char sig = signature;
    // bool sig_present = false;
    // int tempSerialNum;
    RSA rsa;
	
    bool iv[8] = {0,0,0,0,0,0,0,0};

    for(int i = 0; i < temp.length(); i++){
        bool bits[8] = {0,0,0,0,0,0,0,0};
        bool key[10] = {0,0,0,0,0,0,0,0,0,0};
        asciiToBinary(temp[i], bits);
        exclusiveOr(bits, iv, 8); //exclusive or before encrypting with iv
        encrypt(bits, key);
            
        for(int j = 0; j < 8; j++){
            iv[j] = bits[j];
        }
        temp[i] = binaryToAscii(bits);
    }
	// }
    // if(sig_present == true){
    cout<<sig<<" : "<<binaryToAscii(iv)<<endl;
    if(sig != binaryToAscii(iv)){
        return false;
    }
    // }
    
	return true;
}

char CRL::cbcHash(){
	// fstream infile(fileName);
	string temp;
	for(crlobject obj : crlList){
        temp += "Signature Algorithm Identity: ";
        temp += string(obj.signatureAlgorithmIdentity) + "Signature Algorithm Parameters: "+obj.signatureAlgorithmParameters+
                "Issuer Name: " + obj.issuerName + "This Date: "+ to_string(obj.thisDate) + "Next Date: " + to_string(obj.nextDate) + "Revoked Serial Number: "+to_string(obj.revokedSerialNumber)+
                "Revoked Date: " + to_string(obj.revokedDate);
    }
    bool iv[8] = {0,0,0,0,0,0,0,0};

	// while(getline(infile, temp)){
    for(int i = 0; i < temp.length(); i++){
        bool bits[8] = {0,0,0,0,0,0,0,0};
        bool key[10] = {0,0,0,0,0,0,0,0,0,0};
        asciiToBinary(temp[i], bits);
        exclusiveOr(bits, iv, 8); //exclusive or before encrypting with iv
        encrypt(bits, key);
            
        for(int j = 0; j < 8; j++){
            iv[j] = bits[j];
        }
        temp[i] = binaryToAscii(bits);
    }
	// }
    
	return binaryToAscii(iv);
}

crlobject CRL::getObj(int index){
    return crlList.at(index);
}

void CRL::addObj(crlobject obj){
    crlList.push_back(obj);
}

bool CRL::find(int serialNum){
    for(auto const &i: crlList){
        if(i.revokedSerialNumber == serialNum){
            return true;
        }
    }
    return false;
}

int CRL::getNumObj(){
    return crlList.size();
}