#ifndef NETIFEPROBE_SERVERINTERFACE_H
#define NETIFEPROBE_SERVERINTERFACE_H


#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <atomic>
#include <cstdint>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <map>
#include <mswsock.h>

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

#define ALT_PORT 43010
#define SSL_ALT_PORT 34010

constexpr static size_t MaxBufferSize = 1024 * 4; // 1024 * 1; // 最大缓冲区尺寸
constexpr static size_t NumberOfThreads = 100; // 线程池线程数量



// 用于标识IO事件的类型，不与宏定义冲突
enum class EventIOType {
    ServerIORead, // 代理服务器作为服务器端时的 IO 读
    ServerIOWrite,
    ClientIORead, // 代理服务器作为客户端时的 IO 读
    ClientIOWrite,
    ServerIOAccept, // 代理服务器接收到的连接请求
    ClientIOConnect
};


// 用于重叠IO
struct IOContext {
    OVERLAPPED overlapped{};
    CHAR *buffer = nullptr; //[MaxBufferSize];// = new CHAR[MaxBufferSize];  // [MaxBufferSize]{};
    WSABUF wsaBuf{MaxBufferSize, buffer}; // 后面赋值，这里只是说明相关性
    EventIOType type{};
    SOCKET socket = INVALID_SOCKET;
    DWORD nBytes = 0;
    sockaddr_in addr{}; // 保存拆解好的地址
    sockaddr_storage addresses[2]{}; // 保存本地地址和远程地址，第二个是 remote
    SOCKET remoteSocket = INVALID_SOCKET; // 过渡使用的，传递最开始的 accept 后的socket
    std::string sendToClient; // 要回复给客户端的数据
    std::string sendToServer; // 要发给远程服务器的数据
    UINT16 seq = 1; // seq:6 = 1;
    // 一个tcp数据包理论最大值是 65535，1024 * 60，2 的 6 次方是64，刚好可以容纳
    // TODO 后续有时间将 C++ 版本提升至20 并使用使用位域重构
};

class ServerInterface {
public:
    virtual void startServer(_In_ int maxWaitList,
                             _In_ std::map<UINT, UINT32> *mapPortPID) = 0;

private:
    virtual inline int newAccept() = 0;

    virtual inline int newConnect(_In_ IOContext* ioContext) = 0;



    virtual inline int commitData(_In_ const std::string &originData,
                                  _In_ const UINT32 &pid,
                                  _In_ const in_addr &serverAddr,
                                  _In_ const bool &isOutBound,
                                  _Out_ std::string &newData) = 0;

   virtual void eventWorkerThread() = 0;

};


#endif //NETIFEPROBE_SERVERINTERFACE_H
