#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in peer;
    int peer_len = sizeof(peer);

    // Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << "\n";
        return 1;
    }

    // Iterate over possible socket descriptors
    for(SOCKET i = 0; i < 200; i++) {
        memset(&peer, 0, sizeof(peer));
        if(getpeername(i, (struct sockaddr*)&peer, &peer_len) == 0) {
            // Check if the socket is connected to localhost on port 2291
            if(peer.sin_addr.S_un.S_addr == inet_addr("127.0.0.1") && ntohs(peer.sin_port) == 2291) {
                std::cout << "Socket " << i << " is connected to localhost on port 2291\n";
                ConnectSocket = i;
                break;
            }
        }
    }

    if (ConnectSocket == INVALID_SOCKET) {
        std::cout << "No socket found that is connected to localhost on port 2291\n";
    }

    // cleanup
    WSACleanup();

    return 0;
}
