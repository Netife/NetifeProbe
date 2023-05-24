#ifndef __PROXYSERVER_H__
#define __PROXYSERVER_H__

#include "../ServerInterface.h"


class ProxyServer: public ServerInterface{
private:

    LPFN_CONNECTEX pfn_ConnectEx = nullptr;

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
            _In_ const bool &,
            _Out_ std::string &)> &func);

    /**
 * 启动代理服务器
 * @param maxWaitList 最大请求队列
 * @param mapPortPID 用于传输pid的map
 */
    void startServer(_In_ int maxWaitList,
                     _In_ std::map<UINT, UINT32> *mapPortPID) override;


    ~ProxyServer();



private:



    inline static int asyReceive(_In_ IOContext *ioContext,
                          _In_ const SOCKET &socket,
                          _In_ const EventIOType &typeOfReceive);


    inline static int asySend(_In_ IOContext *ioContext,
                       _In_ const SOCKET &socket,
                       _In_ const EventIOType &typeOfSend);


    /**
     * 处理转发任务
     * 此线程用于不断处理 AcceptWorkerThread 所 Post 过来的事件
     */
    void eventWorkerThread() override;

    /**
     * 创建一个新的异步accept
     * @return 错误码
     */
    inline int newAccept() override;

    /**
     * 创建一个新的异步connect
     * @return 错误码
     */
    inline int newConnect(_In_ IOContext* ioContext) override;

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
    inline int commitData(_In_ const std::string &originData,
                   _In_ const UINT32 &pid,
                   _In_ const in_addr &serverAddr,
                   _In_ const bool &isOutBound,
                   _Out_ std::string &newData) override;


};

#endif