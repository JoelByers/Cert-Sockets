#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <cstring>
#include "Cert487.h"
#include "SDES.h"
#include "RSA.h"

using namespace std;

Cert487::Cert487(CertData data){
    this->data = data;
}

Cert487::Cert487(string fileName){
    ifstream fileIn;
    fileIn.open(fileName);
    string input;
    string parsedInput[2] = {"", ""};

    while(!fileIn.eof()){
        fileIn >> input;
        parseCertLine(input, parsedInput);

        if(parsedInput[0].compare("version") == 0){
            data.version = stoi(parsedInput[1]);
        }
        else if(parsedInput[0].compare("serialNumber") == 0){
            data.serialNumber = stoi(parsedInput[1]);
        }
        else if(parsedInput[0].compare("signatureAlgorithmIdentity") == 0){
           strcpy(data.signatureAlgorithmIdentity, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("signatureAlgorithmParameters") == 0){
            strcpy(data.signatureAlgorithmParameters, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("issuerName") == 0){
            strcpy(data.issuerName, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("validNotBefore") == 0){
            data.validNotBefore = stoi(parsedInput[1]);
        }
        else if(parsedInput[0].compare("validNotAfter") == 0){
            data.validNotAfter = stoi(parsedInput[1]);
        }
        else if(parsedInput[0].compare("subjectName") == 0){
            strcpy(data.subjectName, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("publicKeyAlgorithm") == 0){
            strcpy(data.publicKeyAlgorithm, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("publicKeyParameters") == 0){
            strcpy(data.publicKeyParameters, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("publicKey") == 0){
            data.publicKey = stoi(parsedInput[1]);
        }  
        else if(parsedInput[0].compare("issuerUniqueIdentifier") == 0){
            strcpy(data.issuerUniqueIdentifier, parsedInput[1].c_str());
        }      
        else if(parsedInput[0].compare("extensions") == 0){
            strcpy(data.extensions, parsedInput[1].c_str());
        }   
        else if(parsedInput[0].compare("signatureAlgorithm") == 0){
            strcpy(data.signatureAlgorithm, parsedInput[1].c_str());
        }   
        else if(parsedInput[0].compare("signatureParameters") == 0){
            strcpy(data.signatureParameters, parsedInput[1].c_str());
        }
        else if(parsedInput[0].compare("signature") == 0){
            data.signature = parsedInput[1][0];
        }
        else if(parsedInput[0].compare("trust") == 0){
            data.trust = stoi(parsedInput[1]);
        }  
        else{
            cerr << "Invalid Certificate Field \"" << parsedInput[0] << "\"\n";
        }        
    }
    fileIn.close();
}

void Cert487::sign(){
    char hash = cbcHash();
    data.signature = hash;
}

int Cert487::getSerialNumber(){
    return this->data.serialNumber;
}

string Cert487::getIssuer(){
    return this->data.issuerName;
}

string Cert487::getSubjectName(){
    return this->data.subjectName;
}

CertData Cert487::getData(){
    return this->data;
}

void Cert487::parseCertLine(string input, string output[2]){
    output[0] = input.substr(0, input.find("="));
    output[1] = input.substr(input.find("=") + 1, input.length() - 1);
}

void Cert487::printLine(string label, string data){
    cout << setw(30) << left << label << setw(1) << ": " << data << "\n";
}

void Cert487::print(){
    printLine("version", to_string(data.version));
    printLine("serialNumber", to_string(data.serialNumber));
    printLine("signatureAlgorithmIdentity", data.signatureAlgorithmIdentity);
    printLine("signatureAlgorithmParameters", data.signatureAlgorithmParameters);
    printLine("issuerName", data.issuerName);
    printLine("validNotBefore", to_string(data.validNotBefore));
    printLine("validNotAfter", to_string(data.validNotAfter));
    printLine("subjectName", data.subjectName);
    printLine("publicKeyAlgorithm", data.publicKeyAlgorithm);
    printLine("publicKeyParameters", data.publicKeyParameters);
    printLine("publicKey", to_string(data.publicKey));
    printLine("issuerUniqueIdentifier", data.issuerUniqueIdentifier);
    printLine("extensions", data.extensions);
    printLine("signatureAlgorithm", data.signatureAlgorithm);
    printLine("signatureParameters", data.signatureParameters);
    printLine("trust", to_string(data.trust));
    string signature(1, data.signature);
    printLine("signature", signature);
}

void Cert487::printLess(){
    printLine("serialNumber", to_string(data.serialNumber));
    printLine("issuerName", data.issuerName);
    printLine("subjectName", data.subjectName);
}

void Cert487::writeLineToFile(ofstream &fileOut, string label, string data){
    fileOut << label << "=" << data << "\n";
}

void Cert487::writeToFile(string fileName){
    ofstream fileOut;
    fileOut.open(fileName);
    
    writeLineToFile(fileOut, "version", to_string(data.version));
    writeLineToFile(fileOut, "serialNumber", to_string(data.serialNumber));
    writeLineToFile(fileOut, "signatureAlgorithmIdentity", data.signatureAlgorithmIdentity);
    writeLineToFile(fileOut, "signatureAlgorithmParameters", data.signatureAlgorithmParameters);
    writeLineToFile(fileOut, "issuerName", data.issuerName);
    writeLineToFile(fileOut, "validNotBefore", to_string(data.validNotBefore));
    writeLineToFile(fileOut, "validNotAfter", to_string(data.validNotAfter));
    writeLineToFile(fileOut, "subjectName", data.subjectName);
    writeLineToFile(fileOut, "publicKeyAlgorithm", data.publicKeyAlgorithm);
    writeLineToFile(fileOut, "publicKeyParameters", data.publicKeyParameters);
    writeLineToFile(fileOut, "publicKey", to_string(data.publicKey));
    writeLineToFile(fileOut, "issuerUniqueIdentifier", data.issuerUniqueIdentifier);
    writeLineToFile(fileOut, "extensions", data.extensions);
    writeLineToFile(fileOut, "signatureAlgorithm", data.signatureAlgorithm);
    writeLineToFile(fileOut, "signatureParameters", data.signatureParameters);
    writeLineToFile(fileOut, "trust", to_string(data.trust));
    string signature(1, cbcHash());//data.signature);
    writeLineToFile(fileOut, "signature", signature);

    fileOut.close();
}

char Cert487::cbcHash(){
	// fstream infile(fileName);
	// string temp;
    RSA rsa;
    string temp = "version="+to_string(this->data.version)+"serialNumber="+to_string(this->data.serialNumber)+"signatureAlgorithmIdentity="+this->data.signatureAlgorithmParameters+"issuerName="+this->data.issuerName+
    "validNotBefore="+to_string(this->data.validNotBefore)+"validNotAfter="+to_string(this->data.validNotAfter)+"subjectName="+this->data.subjectName+"publicKeyAlgorithm="+this->data.publicKeyAlgorithm+"publicKeyParameters="+this->data.publicKeyParameters+
    "publicKey="+to_string(this->data.publicKey)+"issuerUniqueIdentifier"+this->data.issuerUniqueIdentifier+"extensions="+this->data.extensions+"signatureAlgorithm="+this->data.signatureAlgorithm+"signatureParameters="+this->data.signatureParameters+
    "trust="+to_string(this->data.trust);
    cout<<temp<<endl;
	
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
        // }
	}
    
	return char(rsa.encrypt(binaryToAscii(iv),this->data.publicKey));//char(rsa.encrypt(int(binaryToAscii(iv)), rsa.getE()));
}

bool cbcHashCheck(CertData certDat){
    RSA rsa;
    string temp = "version="+to_string(certDat.version)+"serialNumber="+to_string(certDat.serialNumber)+"signatureAlgorithmIdentity="+certDat.signatureAlgorithmParameters+"issuerName="+certDat.issuerName+
    "validNotBefore="+to_string(certDat.validNotBefore)+"validNotAfter="+to_string(certDat.validNotAfter)+"subjectName="+certDat.subjectName+"publicKeyAlgorithm="+certDat.publicKeyAlgorithm+"publicKeyParameters="+certDat.publicKeyParameters+
    "publicKey="+to_string(certDat.publicKey)+"issuerUniqueIdentifier"+certDat.issuerUniqueIdentifier+"extensions="+certDat.extensions+"signatureAlgorithm="+certDat.signatureAlgorithm+"signatureParameters="+certDat.signatureParameters+
    "trust="+to_string(certDat.trust);
    char sig = certDat.signature;//rsa.decrypt(certDat.signature, rsa.getD());
	// fstream infile(fileName);
	// string temp;
    string temp1;
    string tempSerialString;
    // char sig;
    bool sig_present = false;
    int tempSerialNum;
    //RSA rsa;
	
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
        cout<<sig<<" : "<<char(rsa.encrypt(binaryToAscii(iv),certDat.publicKey))<<endl;
        if(sig != char(rsa.encrypt(binaryToAscii(iv),certDat.publicKey))){
            return false;
        }
    // }
    
	return true;
}