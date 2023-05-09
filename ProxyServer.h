#ifndef __PROXYSERVER_H__
#define __PROXYSERVER_H__

#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <atomic>
#include <cstdint>
#include <vector>
#include <memory>

#include <thread>
#include <mutex>
#include "gRpcServices/NetifePostClientImpl.h"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

#define ALT_PORT 43010
constexpr static size_t MaxBufferSize = 1024 * 1;
constexpr static size_t NumberOfThreads = 100;


// 用于标识事件的类型
enum class IOType {
    Read,
    Write
};


// 用于重叠IO
struct IOContext {
    OVERLAPPED overlapped{};
    WSABUF wsaBuf{ MaxBufferSize, buffer };
    CHAR buffer[MaxBufferSize]{};
    IOType type{};
    SOCKET socket = INVALID_SOCKET;
    DWORD nBytes = 0;
    sockaddr_in addr{};
};




class ProxyServer
{
private:

    // 代理服务器
    SOCKET serverSocketFD = INVALID_SOCKET; // 高性能服务器的文件描述符
    HANDLE hIOCP = INVALID_HANDLE_VALUE; // Windows 重叠IO 之 IOCP ，为高性能而生
    std::vector<std::thread> threadGroup; // 线程组，为高性能而生
	struct sockaddr_in serverSocketAddr{}; // 可重用，重用后是客户端的 socketAddr
    std::atomic_bool isShutdown{ false };

    // 数据交互
    std::map<UINT, UINT32> *mapPortWithPID = nullptr; // 获取 PID，最多 65536 个，内存占用无所谓
	std::mutex myThreadMutex; // 线程锁

    // grpc
    Netife::NetifePostClientImpl client;
public:
	explicit ProxyServer(UINT proxyPort, const string& name, const std::string& port);
	~ProxyServer();

	void startServer(int maxWaitList, std::map<UINT, UINT32> *mapPortPID = nullptr);

    // 此线程用于不断接收连接，并 Post 一次 Read 事件
    void AcceptWorkerThread();
    // 此线程用于不断处理 AcceptWorkerThread 所 Post 过来的事件
    void EventWorkerThread();

private:
/*	int transDataInner(SOCKET getDataSocketFD, SOCKET sendDataSocketFD, BOOL inbound, UINT oriClientPort,
					   struct in_addr serverAddr);*/

	int commitData(const char *const originData, const size_t lenOfOriData,
				   const UINT32 pid, struct in_addr serverAddr,
				   char **newData, size_t *lenOfNewData);
};
#endif