#ifndef __PROXYSERVER_H__
#define __PROXYSERVER_H__


#include <iostream>
#include <WinSock2.h>
#include <thread>
#include <mutex>
#include <map>
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

class ProxyServer
{
private:
	std::map<UINT,UINT32>* mapPortWithPID = nullptr;
	struct sockaddr_in serverSocketAddr {};
	SOCKET serverSocketFD;
	bool isLoop = false;
	std::mutex myThreadMutex;

public:
	ProxyServer(UINT proxyPort);
	~ProxyServer();

	void startServer(int maxWaitList, UINT altPort,	std::map<UINT,UINT32>* mapPortPID = nullptr);

private:
	int transDataInner(SOCKET getDataSocketFD, SOCKET sendDataSocketFD, BOOL inbound, UINT oriClientPort,
                       struct in_addr serverAddr);

	int commitData(const char* const originData,const size_t lenOfOriData,
                   const UINT32 pid, struct in_addr serverAddr,
                   char** newData, size_t* lenOfNewData);

};
#endif