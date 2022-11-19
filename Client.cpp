#include <iostream>   
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include "Cert487.h"

using namespace std;

struct DiffieHellmanServerData{
    int base;
    int mod;
    int serverResult;
};

int main(){
// SETUP CONNECTION /////////////////////////////////////////////////////////////////////////
    // create socket
    int socket_description = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_description == -1){
        cout << "Unable to create socket" << endl;
        return 1;
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr("0.0.0.0");
	server.sin_family = AF_INET;
    server.sin_port = htons(8421);

	if (connect(socket_description , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
        cout << "Unable to connect" << endl;
		return 1;
	}
// RECEIVE CERTS ////////////////////////////////////////////////////////////////////////////
    CertData incomingCert;

    recv(socket_description, &incomingCert, sizeof(incomingCert), 0);

    Cert487 cert(incomingCert);
    cert.print();

// CLOSE CONNECTION /////////////////////////////////////////////////////////////////////////
    close(socket_description);

    return 0;
}