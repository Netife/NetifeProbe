#ifndef __PROXYSERVER_H__
#define __PROXYSERVER_H__


#include <iostream>
#include <WinSock2.h>
#include <thread>
#include <mutex>
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

class ProxyServer
{
private:
	struct sockaddr_in serverSocketAddr {};
	SOCKET serverSocketFD;
	bool isLoop = false;
	std::mutex myThreadMutex;

public:
	ProxyServer(UINT proxyPort);
	~ProxyServer();

	void startServer(int maxWaitList, UINT altPort);

private:
	int transDataInner(SOCKET getDataSocketFD, SOCKET sendDataSocketFD, BOOL inbound);

	int commitData(const char* const originData, size_t lenOfOriData, char** newData, size_t* lenOfNewData);

};
#endif