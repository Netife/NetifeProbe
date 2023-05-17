#ifndef __PROXYSERVER_H__
#define __PROXYSERVER_H__

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
constexpr static size_t MaxBufferSize = 1024 * 4; // 1024 * 1; // 最大缓冲区尺寸
constexpr static size_t NumberOfThreads = 100; // 线程池线程数量


// 用于标识IO事件的类型，不与宏定义冲突
enum class EventIOType {
    ServerIORead, // 代理服务器作为服务器端时的 IO 读
    ServerIOWrite,
    ClientIORead, // 代理服务器作为客户端时的 IO 读
    ClientIOWrite,
    ServerIOAccept // 代理服务器接收到的连接请求
};


// 用于重叠IO
struct IOContext {
    OVERLAPPED overlapped{};
    CHAR* buffer = nullptr; //[MaxBufferSize];// = new CHAR[MaxBufferSize];  // [MaxBufferSize]{};
    WSABUF wsaBuf{MaxBufferSize, buffer}; // 后面赋值，这里只是说明相关性
    EventIOType type{};
    SOCKET socket = INVALID_SOCKET;
    DWORD nBytes = 0;
    sockaddr_in addr{}; // 保存拆解好的地址
    sockaddr_storage addresses[2]{}; // 保存本地地址和远程地址，第二个是 remote
    SOCKET altSocket = INVALID_SOCKET; // 过渡使用的，传递最开始的 accept 后的socket
    std::string sendToClient; // 要回复给客户端的数据
    std::string sendToServer; // 要发给远程服务器的数据
    UINT16 seq = 1; // seq:6 = 1;
    // 一个tcp数据包理论最大值是 65535，1024 * 60，2 的 6 次方是64，刚好可以容纳
    // TODO 后续有时间将 C++ 版本提升至20 并使用使用位域重构
};


class ProxyServer {
private:

    // 代理服务器
    SOCKET serverSocketFD = INVALID_SOCKET; // 高性能服务器的文件描述符
    HANDLE hIOCP = INVALID_HANDLE_VALUE; // Windows 重叠IO 之 IOCP ，为高性能而生
    std::vector<std::thread> threadGroup; // 线程组，为高性能而生
    std::thread acceptThread; // 处理连接请求的线程，为辅助高性能而生
    struct sockaddr_in serverSocketAddr{}; // 可重用，重用后是客户端的 socketAddr
    std::atomic_bool isShutdown{false};

    // 数据交互
    std::map<UINT, UINT32> *mapPortWithPID = nullptr; // 获取 PID，最多 65536 个，内存占用无所谓
    std::mutex myThreadMutex; // 线程锁

    // 无侵入式 grpc 逻辑
    const std::function<int(
            _In_ const std::string &,
            _In_ const UINT32 &,
            _In_ const in_addr &,
            _In_ const bool &,
            _Out_ std::string &
    )> commitDataFunc;


public:


    explicit ProxyServer(_In_ UINT proxyPort,
                         _In_ const std::function<int(
                                 _In_ const std::string &,
                                 _In_ const UINT32 &,
                                 _In_ const in_addr &,
                                 _In_ const bool &,
                                 _Out_ std::string &)>& func);

    ~ProxyServer();


    /**
     * 启动代理服务器
     * @param maxWaitList 最大请求队列
     * @param mapPortPID 用于传输pid的map
     */
    void startServer(_In_ int maxWaitList,
                     _In_ std::map<UINT, UINT32> *mapPortPID = nullptr);


    /**
     * 处理连接请求
     * 此线程用于不断接收连接，并 Post 一次 Read 事件
     */
    void acceptWorkerThread();


    /**
     * 处理转发任务
     * 此线程用于不断处理 AcceptWorkerThread 所 Post 过来的事件
     */
    void eventWorkerThread();

    /**
     * 创建一个新的异步accept
     */
    int newAccept();

private:
    /**
     * 提交数据给其他模块
     * @param originData 原始数据
     * @param pid 流进程 pid
     * @param serverAddr 远程服务器地址
     * @param isOutBound 是否是向外的数据包
     * @param newData 其他模块修改后的新数据
     * @return 错误码
     */
    int commitData(_In_ const std::string &originData,
                   _In_ const UINT32 &pid,
                   _In_ const in_addr &serverAddr,
                   _In_ const bool &isOutBound,
                   _Out_ std::string &newData);


};

#endif