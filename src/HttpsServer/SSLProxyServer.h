#ifndef NETIFEPROBE_SSLPROXYSERVER_H
#define NETIFEPROBE_SSLPROXYSERVER_H


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bioerr.h>
#include <filesystem>
#include <mutex>
#include "../ServerInterface.h"
#include "../utils/ThreadPool.h"

#define FRAMEWORK_ONE

namespace sslServer {
    static std::mutex certMtx;


    // 用于重叠IO
    struct SSLIOContext : public BaseIOContext{
        OVERLAPPED overlapped{};
        CHAR *buffer = nullptr; //[MaxBufferSize];// = new CHAR[MaxBufferSize];  // [MaxBufferSize]{};
        CHAR *remoteBuffer = nullptr;
        WSABUF wsaBuf{MaxBufferSize, buffer}; // 后面赋值，这里只是说明相关性
        WSABUF remoteWsaBuf{MaxBufferSize, remoteBuffer}; // 后面赋值，这里只是说明相关性
        EventIOType type{};
        SOCKET socket = INVALID_SOCKET;
        SOCKET remoteSocket = INVALID_SOCKET;

        SSL *clientSSL = nullptr;
        SSL *remoteSSL = nullptr;
        DWORD nBytes = 0;
        sockaddr_in addr{}; // 保存拆解好的地址
        sockaddr_storage addresses[2]{}; // 保存本地地址和远程地址，第二个是 remote

        BIO * internalBio = nullptr;
        BIO * networkBio = nullptr;

        BIO *remoteInternalBio = nullptr;
        BIO * remoteNetworkBio = nullptr;
        std::string sendToServer;
        std::string sendToServerRaw;
        std::string sendToClient;
        std::string sendToClientRaw;
        SSL_CTX *newClientSSLCtx = nullptr;
        UINT16 seq = 1; // seq:6 = 1;
        UINT16 remoteSeq = 1; // seq:6 = 1;
        // 一个tcp数据包理论最大值是 65535，1024 * 60，2 的 6 次方是64，刚好可以容纳
        // TODO 后续有时间将 C++ 版本提升至20 并使用使用位域重构

        std::mutex* pMtx = nullptr;
        std::condition_variable* pConditionVal = nullptr;

        bool isServerRun = true;
        bool isClientRun = true;

    };


    class SSLProxyServer :virtual public ServerInterface {
    private:
        LPFN_CONNECTEX pfn_ConnectEx = nullptr;
        SSL_CTX *serverSSLCtx = nullptr;
        SSL_CTX* clientSSLCtx = nullptr;

        ThreadPool* pWorkPool = nullptr;

        std::mutex mtx;

        // 代理服务器
        SOCKET serverSocketFD = INVALID_SOCKET; // 高性能服务器的文件描述符
        HANDLE hIOCP = INVALID_HANDLE_VALUE; // Windows 重叠IO 之 IOCP ，为高性能而生
        std::vector<std::thread> threadGroup; // 线程组，为高性能而生
        std::thread acceptThread; // 处理连接请求的线程，为辅助高性能而生
        struct sockaddr_in serverSocketAddr{}; // 可重用，重用后是客户端的 socketAddr


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
        explicit SSLProxyServer(_In_ UINT proxyPort,
                                _In_ const std::function<int(
                _In_ const std::string &,
                _In_ const UINT32 &,
                _In_ const in_addr &,
                _In_ const bool &,
                _In_ const bool &,
                _Out_ std::string &)> &func);



        void startServer(_In_ int maxWaitList,
                         _In_ std::map<UINT, UINT32> *mapPortPID) override;





    private:
        inline static bool checkIfCertFileExists(const std::string &filePath);

        static int clientHelloSelectServerCTX(_In_ SSL *ssl,
                                              _In_ int *ignore,
                                              _In_ void *arg);


        inline int newAccept() override;

        inline int newConnect(_In_ BaseIOContext* baseIoContext) override;



        int commitData(_In_ const std::string &originData,
                       _In_ const UINT32 &pid,
                       _In_ const in_addr &serverAddr,
                       _In_ const bool &isOutBound,
                       _Out_ std::string &newData) override;

        void eventWorkerThread() override;
    };


#endif //NETIFEPROBE_SSLPROXYSERVER_H
};