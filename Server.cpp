#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <cstdlib>
#include <cstring>
#include "Cert487.h"

using namespace std;

struct DiffieHellmanServerData{
    int base;
    int mod;
    int serverResult;
};

int main(int argc, char** argv){

// SETUP CONNECTION /////////////////////////////////////////////////////////////////////////
    // create socket
    int socket_description = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_description == -1){
        cout << "Unable to create socket" << endl;
        return 1;
    }

    struct sockaddr_in server;
    struct sockaddr_in client;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8421);

    // bind to port
    if(bind(socket_description,(struct sockaddr*) &server, sizeof(server)) < 0){
        cout << "Unable to bind to port" << endl;
        return 1;
    }
    cout << "Socket bound, waiting for client..." << endl;

    // listen for client
    listen(socket_description, 3);

    int c = sizeof(struct sockaddr_in);
    int new_socket = accept(socket_description, (struct sockaddr*) &client, (socklen_t*)&c);
    if(new_socket < 0){
        cout << "Failed to accept client connection" << endl;
        return 1;
    }

// SEND CERTS ////////////////////////////////////////////////////////////////////////////

    int numCerts = argc - 1;

    if(send(new_socket , &numCerts, sizeof(numCerts), 0) < 0)
    {
        cout << "Unable to send server data to client";
        return 1;
    }

    for(int i = 0; i < numCerts; i++){
        Cert487 cert(argv[i + 1]);
        cert.printLess();
        cout << "----------------------------------------------------\n";
        CertData data = cert.getData();

        if(send(new_socket , &data, sizeof(cert), 0) < 0)
        {
            cout << "Unable to send server data to client";
            return 1;
        }
    }

// CLOSE CONNECTION /////////////////////////////////////////////////////////////////////////
    close(socket_description);

    return 0;
}