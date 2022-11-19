#include <iostream>   
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include "Cert487.h"
#include "CertGroup.h"

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
    
    CertGroup group;

    int numCerts;
    recv(socket_description, &numCerts, sizeof(numCerts), 0);

    for(int i = 0; i < numCerts; i++){
        CertData incomingCert;
        recv(socket_description, &incomingCert, sizeof(incomingCert), 0);
        Cert487 cert(incomingCert);

        group.addCert(cert);
    }

    group.print();

    int start;
    int end;

    cout << "Enter serial numbers of start and end of chain:" << endl;
    cout << "Start: ";
    cin >> start;
    cout << "End: ";
    cin >> end;
    cout << endl;

    if(group.validateChain(start, end)){
        cout << "A valid chain can be found" << endl;
    }
    else{
        cout << "No valid chain can be found" << endl;
    }

// CLOSE CONNECTION /////////////////////////////////////////////////////////////////////////
    close(socket_description);

    return 0;
}