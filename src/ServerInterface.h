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
#pragma comment(lib, "mswsock.lib")

#define ALT_PORT 43010
#define SSL_ALT_PORT 34010

#define MYPRINT(n) \
    std::cerr << "Line " << __LINE__ << ": " << #n << " = " << n << std::endl

constexpr static size_t MaxBufferSize = 1024 * 4; // 1024 * 1; // 最大缓冲区尺寸
constexpr static size_t MaxNumberOfThreads = 16; // 线程池线程数量

constexpr static char hexTable[] = {
    '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
};

std::string static myToHex(const std::string& srcStr) {
    std::string dstStr{};
    for (const UINT8& ch : srcStr) {
        dstStr.push_back(hexTable[ch >> 4]); // highByte
        dstStr.push_back(hexTable[ch & 0x0F]); // lowBytes

    }

    return dstStr;
}

std::string static myToBytes(const std::string& srcStr) {
    auto len = srcStr.length();
    if (len % 2 != 0) {
        exit(-100);
    }
    std::string dstStr{};
    for (auto i = 1; i < len; i+=2) {
        auto highByte = srcStr.at(i - 1);
        auto lowBytes = srcStr.at(i);
        dstStr.push_back(
            ((lowBytes > '9' ? (lowBytes + 9) : lowBytes) & 0x0F) |
            ((highByte > '9' ? (highByte + 9) : highByte) << 4)
            );
    }
    return dstStr;

}



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

struct BaseIOContext {};


class ServerInterface {

protected:
    size_t numOfWorkerThreads = MaxNumberOfThreads;
public:
    virtual void startServer(_In_ int maxWaitList,
                             _In_ std::map<UINT, UINT32> *mapPortPID) = 0;

protected:
    virtual inline int newAccept() = 0;

    virtual inline int newConnect(_In_ BaseIOContext* baseIoContext) = 0;



    virtual inline int commitData(_In_ const std::string &originData,
                                  _In_ const UINT32 &pid,
                                  _In_ const in_addr &serverAddr,
                                  _In_ const bool &isOutBound,
                                  _Out_ std::string &newData) = 0;

   virtual void eventWorkerThread() = 0;

};


#endif //NETIFEPROBE_SERVERINTERFACE_H
