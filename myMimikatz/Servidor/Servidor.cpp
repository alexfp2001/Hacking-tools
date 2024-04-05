#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "Ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET listeningSocket = INVALID_SOCKET, clientSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, hints;
    int iResult;

    // Inicializar Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // Dirección IPv4
    hints.ai_socktype = SOCK_STREAM; // Socket de flujo TCP
    hints.ai_protocol = IPPROTO_TCP; // Protocolo TCP
    hints.ai_flags = AI_PASSIVE; // Usar la dirección IP de mi máquina

    // Resolver la dirección y el puerto local donde escuchar
    iResult = getaddrinfo(NULL, "3311", &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    // Crear un SOCKET para escuchar conexiones de clientes
    listeningSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listeningSocket == INVALID_SOCKET) {
        std::cerr << "Error at socket(): " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Configurar el TCP listening socket
    iResult = bind(listeningSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "bind failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(listeningSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    // Aceptar una conexión de cliente
    clientSocket = accept(listeningSocket, NULL, NULL);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "accept failed: " << WSAGetLastError() << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    // No necesitamos más el listening socket
    closesocket(listeningSocket);

    // Buffer para recibir datos
    const int bufferSize = 512;
    char recvbuf[bufferSize];
    int recvbuflen = bufferSize;
    std::ofstream outputFile("received_dump.dmp", std::ios::binary);

    // Recibir datos hasta que el cliente cierre la conexión
    do {
        iResult = recv(clientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {
            outputFile.write(recvbuf, iResult);
        }
        else if (iResult == 0) {
            std::cout << "Connection closing...\n";
        }
        else {
            std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
        }
    } while (iResult > 0);

    // Limpiar
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}

