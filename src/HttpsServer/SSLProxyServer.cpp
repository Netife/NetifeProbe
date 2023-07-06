#include "SSLProxyServer.h"
#include <cassert>
#include <string>
#include <condition_variable>
#include "../utils/SafeMap.h"

using namespace sslServer;

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")
#define CERT_GEN
#define aaa
constexpr bool isDebug = true;
// perror 后面会跟上系统错误码
static inline std::tuple<bool,int> check_if_fatal_error(_In_ int err) {
    switch (err) {
#define PER_ERROR(x) case x: {if constexpr (!isDebug) perror("ssl code: "#x"\n"); return {false,x};} 

        PER_ERROR(SSL_ERROR_NONE)
            PER_ERROR(SSL_ERROR_WANT_READ)
            PER_ERROR(SSL_ERROR_WANT_WRITE)
            PER_ERROR(SSL_ERROR_WANT_CONNECT)
            PER_ERROR(SSL_ERROR_WANT_ACCEPT)
    }
    return { true, err };
}















int static asyReceive(_In_ SSLIOContext* ioContext,
    _In_ const SOCKET& socket,
    _In_ const EventIOType& typeOfReceive) {
    // 临时存值
    DWORD dwFlags = 0;
    DWORD nBytes = MaxBufferSize;

    // 表示接收
    ioContext->type = typeOfReceive;

    auto rtOfReceive = WSARecv(
        socket,
        &ioContext->wsaBuf,
        1,
        &nBytes, // 接收到的数据长度
        &dwFlags,
        &ioContext->overlapped,
        nullptr);
    auto errReceive = WSAGetLastError();
    if (SOCKET_ERROR == rtOfReceive && ERROR_IO_PENDING != errReceive) {
        std::cerr << "err occur when receiving data..."
            << WSAGetLastError()
            << std::endl;
        // 发生不为 ERROR_IO_PENDING 的错误
        shutdown(ioContext->socket, SD_BOTH);
        closesocket(ioContext->socket);
        delete[]ioContext->buffer;

        delete ioContext;
        ioContext = nullptr;
        assert(0);
        return -1;
    }

    return 0;


}



int static asySend(_In_ SSLIOContext* ioContext,
    _In_ const SOCKET& socket,
    _In_ const EventIOType& typeOfSend) {

    // 临时存值
    DWORD dwFlags = 0;
    DWORD nBytes = MaxBufferSize;

    // 发送类型
    ioContext->type = typeOfSend;

    auto rtOfSend = WSASend(
        socket,
        &ioContext->wsaBuf,
        1,
        &nBytes,  // 用不上
        dwFlags,
        &(ioContext->overlapped),
        nullptr);
    auto errSend = WSAGetLastError();
    if (SOCKET_ERROR == rtOfSend && errSend != WSAGetLastError()) {
        std::cerr << "err occur when sending data... "
            << WSAGetLastError()
            << std::endl;
        // 返回信息发生错误
        closesocket(ioContext->socket);
        ioContext->sendToClient.clear();
        ioContext->sendToServer.clear();

        // 缓冲区由string管理
        delete ioContext;
        ioContext = nullptr;
        assert(0);
        return -1;
    }


    return 0;
}


int static readUntilNoData(_In_ BaseIOContext* baseIoContext,
    _In_ DWORD lpNumberOfBytesTransferred) {

    auto ioContext = reinterpret_cast<SSLIOContext*>(baseIoContext);

    const SOCKET* curSocket = nullptr;
    switch (ioContext->type) {
    case EventIOType::ServerIORead: 
    case EventIOType::ServerIOHandshake:
    {
        curSocket = &ioContext->socket;
        break;
    }
    case EventIOType::ClientIORead: 
    case EventIOType::ClientIOHandshake:
    {
        curSocket = &ioContext->remoteSocket;
        break;
    }

    default: {
        assert(0);
        return -1;
        break;
    }
    }


    ioContext->nBytes += lpNumberOfBytesTransferred;
    if (MaxBufferSize > lpNumberOfBytesTransferred) return 0;

    if (MaxBufferSize == lpNumberOfBytesTransferred) {
        auto newBuf = new CHAR[MaxBufferSize * ((ioContext->seq) + 1)]{};
        memmove(newBuf,
            ioContext->buffer,
            MaxBufferSize * (ioContext->seq));
        delete[] ioContext->buffer;
        ioContext->buffer = newBuf;
        ioContext->wsaBuf = {
                static_cast<ULONG>(MaxBufferSize),
                ioContext->buffer + MaxBufferSize * (ioContext->seq)
        };
        ++(ioContext->seq);

        asyReceive(ioContext,
            *curSocket,
            ioContext->type);
        return 1;

    }
    assert(0);
    return -1;

}


SSLProxyServer::SSLProxyServer(_In_ UINT proxyPort,
                               _In_ const std::function<int(
        _In_ const std::string &,
        _In_ const UINT32 &,
        _In_ const in_addr &,
        _In_ const bool &,
        _In_ const bool &,
        _Out_ std::string &)> &func
) : commitDataFunc(func) {

    // init
    WORD ver = MAKEWORD(2, 2);
    WSADATA wd;
    if (WSAStartup(ver, &wd) != 0) {
        assert(0);
    }
    /*
    * 初始化 OpenSSL 库
    */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *serverMethod = SSLv23_server_method();
    serverSSLCtx = SSL_CTX_new(serverMethod);

    const SSL_METHOD* clientMethod = SSLv23_client_method();
    clientSSLCtx = SSL_CTX_new(clientMethod);
    //if (SSL_CTX_use_certificate_file(serverSSLCtx, "cache\\www.baidu.com.crt", SSL_FILETYPE_PEM) <= 0) {
    //	ERR_print_errors_fp(stderr);
    //	exit(EXIT_FAILURE);
    //}

    //if (SSL_CTX_use_PrivateKey_file(serverSSLCtx, "cache\\www.baidu.com.key", SSL_FILETYPE_PEM) <= 0) {
    //	ERR_print_errors_fp(stderr);
    //	exit(EXIT_FAILURE);
    //}

    SSL_CTX_set_client_hello_cb(serverSSLCtx,
                                clientHelloSelectServerCTX,
                                serverSSLCtx);


    serverSocketFD = WSASocketW(
            AF_INET,
            SOCK_STREAM,
            0,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED);
    if (INVALID_SOCKET == serverSocketFD) {
        closesocket(serverSocketFD);
        std::cerr << "failed to create socket: " << WSAGetLastError() << std::endl;
        exit(-2);
    }


    sockaddr_in serverAddr{};
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(proxyPort);

    ::bind(serverSocketFD, (sockaddr *) &serverAddr, sizeof(sockaddr_in));

}

int SSLProxyServer::newAccept() {
    //puts("aaaaa\n");
    // 这里创建最初的 io上下文
    auto ioContext = new SSLIOContext;
    //std::cout << sizeof(SSLIOContext) << std::endl;
    ioContext->type = EventIOType::ServerIOAccept;
    //提前准备好 clientSocketFD
    ioContext->socket = WSASocket(AF_INET,
                                  SOCK_STREAM,
                                  IPPROTO_TCP,
                                  nullptr,
                                  0,
                                  WSA_FLAG_OVERLAPPED);






    // 切记，也要和iocp绑定，不然后续send recv事件没办法通知
    if (nullptr == CreateIoCompletionPort(
            (HANDLE) ioContext->socket,
            hIOCP,
            0,
            0)) {
        shutdown(ioContext->socket, SD_BOTH);
        closesocket(ioContext->socket);
        exit(-15);
    }

    //存放网络地址的长度
    int addrLen = sizeof(sockaddr_storage);


    int bRetVal = AcceptEx(serverSocketFD,
                           ioContext->socket,
                           ioContext->addresses,
                           0,
                           addrLen,
                           addrLen,
                           nullptr,
                           &ioContext->overlapped);
    if (bRetVal == FALSE) {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
            std::cerr << WSAGetLastError() << std::endl;
            closesocket(ioContext->socket);
            return -1;
        }
    }



    // 套壳ssl
    ioContext->clientSSL = SSL_new(serverSSLCtx);
    //assert(!SSL_is_init_finished(ioContext->clientSSL));

    SSL_set_fd(ioContext->clientSSL, ioContext->socket);
    //BIO_new_bio_pair(&ioContext->internalBio,
    //    MaxBufferSize, 
    //    &ioContext->networkBio,
    //    MaxBufferSize);

    
    //ioContext->internalBio = BIO_new(BIO_s_mem());
    //ioContext->networkBio = BIO_new(BIO_s_mem());


    //// 关联这对儿 bio
    //SSL_set_bio(ioContext->clientSSL,
    //            ioContext->internalBio,
    //            ioContext->networkBio);
    SSL_set_accept_state(ioContext->clientSSL);


    return 0;
}

int SSLProxyServer::newConnect(_In_ BaseIOContext * baseIoContext) {

    auto sslIOContext = reinterpret_cast<SSLIOContext *>(baseIoContext);

    WCHAR ipDotDec[20]{};
    InetNtop(AF_INET,
        (void*)&sslIOContext->addr.sin_addr,
        ipDotDec,
        sizeof(ipDotDec));

    std::wcout << "connecting: " << ipDotDec << std::endl;


    sockaddr_in remoteServerAddr{};
    remoteServerAddr.sin_family = AF_INET;
    remoteServerAddr.sin_port = htons(SSL_ALT_PORT);
    remoteServerAddr.sin_addr = sslIOContext->addr.sin_addr;



    // 这里开始 IOCP，创建新的客户端IO文件描述符，alt表示远程服务器
    sslIOContext->remoteSocket = WSASocketW(
            AF_INET,
            SOCK_STREAM,
            0,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED);
    if (INVALID_SOCKET == sslIOContext->remoteSocket) {
        closesocket(sslIOContext->remoteSocket);
        std::cerr << "failed to create socket: "
                  << WSAGetLastError()
                  << std::endl;
        exit(-9);
    }



    setsockopt(sslIOContext->remoteSocket,
    	SOL_SOCKET,
    	SO_UPDATE_CONNECT_CONTEXT,
    	nullptr,
    	0);



    // 和完成端口关联起来
    if (nullptr == CreateIoCompletionPort(
            (HANDLE) sslIOContext->remoteSocket,
            hIOCP,
            0,
            0)) {
        shutdown(sslIOContext->remoteSocket, SD_BOTH);
        closesocket(sslIOContext->remoteSocket);
        closesocket(sslIOContext->socket);
        assert(0);
    }


    addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    addrinfo *pAddrInfo = nullptr;
    if (auto err = getaddrinfo(nullptr,
                               "",
                               &hints,
                               &pAddrInfo)) {

        fprintf(stderr, "getaddrinfo: %ls\n",
                gai_strerror(err));
        exit(-1);
    }
    if (SOCKET_ERROR == ::bind(sslIOContext->remoteSocket,
                               pAddrInfo->ai_addr,
                               static_cast<int>(pAddrInfo->ai_addrlen))) {

    }
    sslIOContext->type = EventIOType::ClientIOConnect;

    // 获取connectEx指针
    if (nullptr == pfn_ConnectEx) {
        DWORD dwRetBytes = 0;
        GUID guid = WSAID_CONNECTEX;
        WSAIoctl(sslIOContext->remoteSocket,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 (void *) &guid,
                 sizeof(guid),
                 (void *) &pfn_ConnectEx,
                 sizeof(pfn_ConnectEx),
                 &dwRetBytes,
                 nullptr,
                 nullptr);
    }

    (*pfn_ConnectEx)(sslIOContext->remoteSocket,
                     (sockaddr *) &remoteServerAddr,
                     sizeof(sockaddr_in), nullptr, 0, nullptr,
                     &sslIOContext->overlapped);




    sslIOContext->remoteSSL = SSL_new(clientSSLCtx);


    assert(!SSL_is_init_finished(sslIOContext->remoteSSL));

    //sslIOContext->remoteInternalBio = BIO_new(BIO_s_mem());
    //sslIOContext->remoteNetworkBio = BIO_new(BIO_s_mem());


    //SSL_set_bio(sslIOContext->remoteSSL,
    //            sslIOContext->remoteInternalBio,
    //            sslIOContext->remoteNetworkBio);


    SSL_set_fd(sslIOContext->remoteSSL, sslIOContext->remoteSocket);
    SSL_set_connect_state(sslIOContext->remoteSSL);


    return 0;
}

void SSLProxyServer::startServer(_In_ int maxWaitList,
                                 _In_ std::map<UINT, UINT32> *mapPortPID) {

    if (SOCKET_ERROR == ::listen(
            serverSocketFD,
            SOMAXCONN)) {
        std::cerr << "failed to listen socket: " << WSAGetLastError() << std::endl;
        closesocket(serverSocketFD);
        exit(-5);
    }


    // 初始化 IOCP
    hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                   nullptr,
                                   0,
                                   0);
    if (INVALID_HANDLE_VALUE == hIOCP) {
        std::cerr << "FAILED TO CREATE IOCP HANDLE:" << WSAGetLastError() << std::endl;
        closesocket(serverSocketFD);
        exit(-6);
    }


    // 切记，先把serverSockerFD和iocp绑定，不然接收不到连接通知
    if (nullptr == CreateIoCompletionPort(
            (HANDLE)serverSocketFD,
            hIOCP,
            0,
            0)) {
        shutdown(serverSocketFD, SD_BOTH);
        closesocket(serverSocketFD);
        exit(-13);
    }


    // 初始化工作线程
    for (size_t i = 0; i < MaxNumberOfThreads; i++) {
        threadGroup.emplace_back([this]() { eventWorkerThread(); });
    }


    // 启动工作线程
    for (auto& t : threadGroup) {
        t.detach();
    }


    for (auto i = 0; i < 1; i++) {
        newAccept();

    }


}

int SSLProxyServer::commitData(_In_ const std::string &originData,
                               _In_ const UINT32 &pid,
                               _In_ const in_addr &serverAddr,
                               _In_ const bool &isOutBound, std::string &newData) {


    return this->commitDataFunc(originData,
                                pid,
                                serverAddr,
                                isOutBound,
                                true,
                                newData);
}

void SSLProxyServer::eventWorkerThread() {
    //puts("worker");
    SSLIOContext *ioContext = nullptr;
    DWORD lpNumberOfBytesTransferred = 0;
    void *lpCompletionKey = nullptr;

    while (true) {
        BOOL bRt = GetQueuedCompletionStatus(
                hIOCP,
                &lpNumberOfBytesTransferred,
                (PULONG_PTR) &lpCompletionKey,
                (LPOVERLAPPED *) &ioContext,
                INFINITE);

        // IO 未完成

        if (!bRt) continue;

        // 收到 PostQueuedCompletionStatus 发出的退出指令
        if (lpNumberOfBytesTransferred == -1) break;

        // 没有可操作数据，但是是连接请求，需要接受！
        if (lpNumberOfBytesTransferred == 0) {
            switch (ioContext->type) {
                case EventIOType::ServerIOAccept:
                case EventIOType::ClientIOConnect:
                    //case EventIOType::ServerIOHandshake:
                    //case EventIOType::ClientIOHandshake:
                    //assert(0);
                    break;



                default:
                    continue;
            }
        }


        // 处理对应的事件

        switch (ioContext->type) {
            case EventIOType::ServerIOAccept: {

                puts("accept!\n");
                newAccept();

                auto newAddr =
                    *reinterpret_cast<sockaddr_in*>
                    (&ioContext->addresses[1]);

                WCHAR ipDotDec[20]{};
                InetNtop(AF_INET,
                    (void*)&newAddr.sin_addr,
                    ipDotDec,
                    sizeof(ipDotDec));
                std::wcout << L"new accept event: to " << ipDotDec << std::endl;

                ioContext->addr = newAddr;
                newConnect(ioContext);
                break;
            }
            case EventIOType::ClientIOConnect: {
                puts("connect finished...\n");
                

                auto r = SSL_do_handshake(ioContext->clientSSL);
                auto err = SSL_get_error(ioContext->clientSSL, r);
//                assert(r == 1);
if (r != 1)break;
                auto r2 = SSL_do_handshake(ioContext->remoteSSL);
                auto err2 = SSL_get_error(ioContext->remoteSSL, r2);
//                assert(r2 == 1);
if (r2!=1)break;

#ifdef aaa


                std::thread([=] {
                    while (1) {
                        char buf[MaxBufferSize]{};
                        std::string res;
                        while (true) {
                            auto rt = SSL_read(ioContext->clientSSL, buf, sizeof(buf));
                            if (rt < 0) {
                                //SSL_shutdown(ioContext->clientSSL);
                                //SSL_free(ioContext->clientSSL);
                                //closesocket(ioContext->socket);
                                return;
                            }
                            res.append(buf, rt);
                            if (rt < MaxBufferSize)break;
                        }

                        ioContext->sendToServerRaw.clear();

                        commitData(res, 0, ioContext->addr.sin_addr, true, ioContext->sendToServerRaw);
                        //std::cout << ioContext->sendToServerRaw << std::endl;

                        auto t1 = SSL_write(ioContext->remoteSSL,
                            ioContext->sendToServerRaw.c_str(),
                            ioContext->sendToServerRaw.length());



                    }
                    }).detach();

                    std::thread([=] {
                        while (1) {
                            char buf[MaxBufferSize]{};
                            std::string res;
                            while (true) {
                                auto rt = SSL_read(ioContext->remoteSSL, buf, sizeof(buf));
                                if (rt < 0) {
                                    //SSL_shutdown(ioContext->remoteSSL);
                                    //SSL_free(ioContext->remoteSSL);
                                    //closesocket(ioContext->remoteSocket);
                                    //ioContext->remoteSSL = nullptr;
                                    //if (ioContext->clientSSL == nullptr)delete ioContext;
                                    return;
                                }
                                res.append(buf, rt);
                                if (rt < MaxBufferSize)break;

                            }

                            ioContext->sendToClientRaw.clear();

                            commitData(res, 0, ioContext->addr.sin_addr, false, ioContext->sendToClientRaw);
                            //std::cout << ioContext->sendToClientRaw << std::endl;


                            auto t1 = SSL_write(ioContext->clientSSL,
                                ioContext->sendToClientRaw.c_str(),
                                ioContext->sendToClientRaw.length());

                        }

                        }).detach();





                        break;

#else

                // 准备线程同步条件变量

                ioContext->pMtx = new std::mutex{};
                ioContext->pConditionVal = new std::condition_variable{};


                
                // 与客户端TLS握手
                auto r = SSL_do_handshake(ioContext->clientSSL);
                int err = SSL_get_error(ioContext->clientSSL, r);
                auto [isFatal, errCode] = check_if_fatal_error(err);

                assert(!isFatal);

                assert(r == -1);
                if (SSL_ERROR_WANT_READ == errCode) {
                    ioContext->buffer = new CHAR[MaxBufferSize]{};
                    ioContext->wsaBuf = {
                        MaxBufferSize,
                        ioContext->buffer
                    };

                    asyReceive(ioContext,
                        ioContext->socket,
                        EventIOType::ServerIOHandshake);
                }
                else {
                    assert(0);
                }
                




                // 与远程服务器TLS握手
                auto newIOContext = new SSLIOContext;
                newIOContext->socket = ioContext->socket;
                newIOContext->clientSSL = ioContext->clientSSL;
                newIOContext->internalBio = ioContext->internalBio;
                newIOContext->networkBio = ioContext->networkBio;


                newIOContext->remoteSocket = ioContext->remoteSocket;
                newIOContext->remoteSSL = ioContext->remoteSSL;
                newIOContext->remoteInternalBio = ioContext->remoteInternalBio;
                newIOContext->remoteNetworkBio = ioContext->remoteNetworkBio;

                newIOContext->addr = ioContext->addr;


                newIOContext->pMtx = ioContext->pMtx;
                newIOContext->pConditionVal = ioContext->pConditionVal;




                auto r_ = SSL_do_handshake(newIOContext->remoteSSL);
                auto err_ = SSL_get_error(newIOContext->remoteSSL, r_);
                auto [isFatal_, errCode_] = check_if_fatal_error(err_);
                assert(!isFatal_);

                assert(r_ == -1);
                if (SSL_ERROR_WANT_READ == errCode_) {
                    ULONG pendingDataLen = BIO_ctrl_pending(newIOContext->remoteNetworkBio);
                    auto pendingDataBuf = new CHAR[pendingDataLen]{};
                    BIO_read(newIOContext->remoteNetworkBio, pendingDataBuf, pendingDataLen);
                    newIOContext->wsaBuf = {
                        pendingDataLen,
                        pendingDataBuf
                    };
                    asySend(newIOContext,
                        newIOContext->remoteSocket,
                        EventIOType::ClientIOWrite);

                }
                else {
                    assert(0);
                }

               
                break;


          




              


                break;
            }
            case EventIOType::ServerIOHandshake: {
                if (1 == readUntilNoData(ioContext, lpNumberOfBytesTransferred)) {
                    continue;
                }

                auto bytesIn = BIO_write(ioContext->internalBio,
                    ioContext->buffer,
                    ioContext->nBytes);
                assert(bytesIn == ioContext->nBytes);
                MYPRINT(bytesIn);


                delete[]ioContext->buffer;
                ioContext->buffer = nullptr;
                ioContext->seq = 1;
                ioContext->nBytes = 0;



                auto r = SSL_do_handshake(ioContext->clientSSL);
                auto err = SSL_get_error(ioContext->clientSSL, r);
                auto [isFatal, errCode] = check_if_fatal_error(err);
                //assert(!isFatal);
                if (isFatal) {
                    
                    assert(errCode == SSL_ERROR_SSL);
                    // 清理io上下文
                    break;

                }





                if (r == 1) {

                    std::unique_lock<std::mutex> lock(*ioContext->pMtx);
                    ioContext->pConditionVal->wait(lock);
                    perror("ServerHandshake finished!\n");
                    lock.unlock();


                    CHAR rawText[MaxBufferSize]{};

                    int rawLen = 0;
                    //std::string res;
                    while ((rawLen = SSL_read(ioContext->clientSSL, rawText, MaxBufferSize)) > 0) {
                        ioContext->sendToServerRaw.append(rawText, rawLen);
                        if (rawLen < MaxBufferSize)break;
                    }

                    auto err = SSL_get_error(ioContext->clientSSL, rawLen);
                    auto [isFatal, errCode] = check_if_fatal_error(err);
                    assert(!isFatal);

                    MYPRINT(errCode);
                    if (SSL_ERROR_WANT_READ == errCode) {
                        assert(rawLen == -1);
                        ioContext->buffer = new CHAR[MaxBufferSize]{};
                        ioContext->wsaBuf = {
                            MaxBufferSize,
                            ioContext->buffer
                        };
                        asyReceive(ioContext, ioContext->socket, EventIOType::ServerIORead);
                        break;


                    }
                    else {
                        MYPRINT(errCode);
                    }

                    commitData(ioContext->sendToServerRaw, 0, ioContext->addr.sin_addr, true, ioContext->sendToServerRaw);

                    MYPRINT(ioContext->sendToServerRaw.length());


                    auto sslBytesIn = SSL_write(ioContext->remoteSSL,
                        ioContext->sendToServerRaw.c_str(),
                        ioContext->sendToServerRaw.length());

                    assert(sslBytesIn == ioContext->sendToServerRaw.length());

                    
                    ULONG remotePendingDataLen = BIO_ctrl_pending(ioContext->remoteNetworkBio);
                    auto remotePendingDataBuf = new CHAR[remotePendingDataLen]{};
                    auto bytesOut = BIO_read(ioContext->remoteNetworkBio, remotePendingDataBuf, remotePendingDataLen);

                    assert(bytesOut == remotePendingDataLen);
                    
                    ioContext->wsaBuf = {
                        remotePendingDataLen,
                        remotePendingDataBuf
                    };

                    MYPRINT(remotePendingDataLen);

                    asySend(ioContext, 
                        ioContext->remoteSocket, 
                        EventIOType::ClientIOWrite);
                    

                }
                else {
                    ULONG pendingDataLen = BIO_ctrl_pending(ioContext->networkBio);
                    auto pendingDataBuf = new CHAR[pendingDataLen]{};
                    BIO_read(ioContext->networkBio, pendingDataBuf, pendingDataLen);
                    ioContext->wsaBuf = {
                        pendingDataLen,
                        pendingDataBuf
                    };
                    asySend(ioContext, ioContext->socket, EventIOType::ServerIOWrite);


                }

#endif


                break;
            }
            case EventIOType::ClientIOHandshake: {
                if (1 == readUntilNoData(ioContext, lpNumberOfBytesTransferred)) {
                    continue;
                }

                auto bytesIn = BIO_write(ioContext->remoteInternalBio,
                    ioContext->buffer,
                    ioContext->nBytes);
                assert(bytesIn == ioContext->nBytes);
                MYPRINT(bytesIn);

                delete[]ioContext->buffer;
                ioContext->buffer = nullptr;
                ioContext->seq = 1;
                ioContext->nBytes = 0;




                auto r = SSL_do_handshake(ioContext->remoteSSL);
                auto err = SSL_get_error(ioContext->remoteSSL, r);
                auto [isFatal, errCode] = check_if_fatal_error(err);

                //assert(!isFatal);
                if (isFatal) {
                    assert(SSL_ERROR_SSL == errCode);
                    ioContext->pConditionVal->notify_all();

                    // 清理io上下文
                    break;
                }

                if (r == 1) {

                    std::unique_lock<std::mutex> lock(*ioContext->pMtx);
                    perror("ClientHandshake finished!\n");
                    ioContext->pConditionVal->notify_one();
                    //assert(0);
                    lock.unlock();


                    ioContext->buffer = new CHAR[MaxBufferSize]{};
                    ioContext->wsaBuf = {
                        MaxBufferSize,
                        ioContext->buffer
                    };

                    asyReceive(ioContext,
                        ioContext->remoteSocket,
                        EventIOType::ClientIORead);
                    

                }
                else {
                    ULONG pendingDataLen = BIO_ctrl_pending(ioContext->remoteNetworkBio);
                    auto pendingDataBuf = new CHAR[pendingDataLen]{};
                    BIO_read(ioContext->remoteNetworkBio, pendingDataBuf, pendingDataLen);
                    ioContext->wsaBuf = {
                        pendingDataLen,
                        pendingDataBuf
                    };
                    asySend(ioContext, ioContext->remoteSocket, EventIOType::ClientIOWrite);


                }

                

                break;
            }
            case EventIOType::ServerIORead: {
                if (1 == readUntilNoData(ioContext, lpNumberOfBytesTransferred)) {
                    continue;
                }
                //assert(0);

                auto bytesIn = BIO_write(ioContext->internalBio,
                    ioContext->buffer,
                    ioContext->nBytes);
                assert(bytesIn == ioContext->nBytes);

                MYPRINT("ServerIORead: " << bytesIn);

                delete[]ioContext->buffer;
                ioContext->buffer = nullptr;
                ioContext->seq = 1;
                ioContext->nBytes = 0;

                CHAR rawText[MaxBufferSize]{};

                //std::string res;
                size_t rawLen = 0;
                while ((rawLen = SSL_read(ioContext->clientSSL, rawText, MaxBufferSize)) > 0) {
                    ioContext->sendToServerRaw.append(rawText, rawLen);
                    if (rawLen < MaxBufferSize)break;
                }
                auto err = SSL_get_error(ioContext->clientSSL, rawLen);
                auto [isFatal, errCode] = check_if_fatal_error(err);
                assert(!isFatal);

                MYPRINT(errCode);
                if (SSL_ERROR_WANT_READ == errCode) {
                    assert(rawLen == -1);
                    ioContext->buffer = new CHAR[MaxBufferSize]{};
                    ioContext->wsaBuf = {
                        MaxBufferSize,
                        ioContext->buffer
                    };
                    asyReceive(ioContext, ioContext->socket, EventIOType::ServerIORead);
                    break;


                }

              
          
                commitData(ioContext->sendToServerRaw,
                    0, 
                    ioContext->addr.sin_addr,
                    true,
                    ioContext->sendToServerRaw);

                MYPRINT(ioContext->sendToServerRaw.length());


                auto sslBytesIn = SSL_write(ioContext->remoteSSL,
                    ioContext->sendToServerRaw.c_str(),
                    ioContext->sendToServerRaw.length());


                

                ULONG remotePendingDataLen = BIO_ctrl_pending(ioContext->remoteNetworkBio);
                auto remotePendingDataBuf = new CHAR[remotePendingDataLen]{};
                BIO_read(ioContext->remoteNetworkBio, remotePendingDataBuf, remotePendingDataLen);


                ioContext->wsaBuf = {
                    remotePendingDataLen,
                    remotePendingDataBuf
                };

                MYPRINT(remotePendingDataLen);

                asySend(ioContext, ioContext->remoteSocket, EventIOType::ClientIOWrite);





              
                break;
            }

            case EventIOType::ClientIOWrite: {

                ioContext->buffer = new CHAR[MaxBufferSize]{};
                ioContext->wsaBuf = {
                    MaxBufferSize,
                    ioContext->buffer
                };
                if (SSL_is_init_finished(ioContext->remoteSSL)) {
                    ioContext->sendToServerRaw.clear();
                    asyReceive(ioContext, ioContext->socket, EventIOType::ServerIORead);
                }
                else {
                    asyReceive(ioContext, ioContext->remoteSocket, EventIOType::ClientIOHandshake);


                }


                break;
            }


            case EventIOType::ServerIOWrite: {

                ioContext->buffer = new CHAR[MaxBufferSize]{};
                ioContext->wsaBuf = {
                    MaxBufferSize,
                    ioContext->buffer
                };
                if (SSL_is_init_finished(ioContext->clientSSL)) {
                    ioContext->sendToClientRaw.clear();
                    asyReceive(ioContext, ioContext->remoteSocket, EventIOType::ClientIORead);

                }
                else {
                    asyReceive(ioContext, ioContext->socket, EventIOType::ServerIOHandshake);
                }

                break;
            }

            case EventIOType::ClientIORead: {
                if (1 == readUntilNoData(ioContext, lpNumberOfBytesTransferred)) {
                    continue;
                }
                

                auto bytesIn = BIO_write(ioContext->remoteInternalBio,
                    ioContext->buffer,
                    ioContext->nBytes);
                assert(bytesIn == ioContext->nBytes);

                MYPRINT("ClientIORead: " << bytesIn);

                delete[]ioContext->buffer;
                ioContext->buffer = nullptr;
                ioContext->seq = 1;
                ioContext->nBytes = 0;

                CHAR rawText[MaxBufferSize]{};

                int rawLen = 0;
                // 发往客户端！
                while ((rawLen = SSL_read(ioContext->remoteSSL, rawText, MaxBufferSize)) > 0) {
                    ioContext->sendToClientRaw.append(rawText, rawLen);
                    if (rawLen < MaxBufferSize)break;
                }
                
                auto err = SSL_get_error(ioContext->remoteSSL, rawLen);
                auto [isFatal,errCode] = check_if_fatal_error(err);
                //assert(!isFatal);

                if (isFatal) {
                    ioContext->pConditionVal->notify_all();
                    MYPRINT("ClientIORead error\n"<<std::to_string(err));
                    break;
                }

                MYPRINT(errCode);
                if (SSL_ERROR_WANT_READ == errCode) {
                    assert(rawLen == -1);
                    ioContext->buffer = new CHAR[MaxBufferSize]{};
                    ioContext->wsaBuf = {
                        MaxBufferSize,
                        ioContext->buffer
                    };
                    asyReceive(ioContext, ioContext->remoteSocket, EventIOType::ClientIORead);
                    break;


                }

                commitData(ioContext->sendToClientRaw,
                    0, ioContext->addr.sin_addr,
                    true,
                    ioContext->sendToClientRaw);

                MYPRINT(ioContext->sendToClientRaw.length());


                auto sslBytesIn = SSL_write(ioContext->clientSSL,
                    ioContext->sendToClientRaw.c_str(),
                    ioContext->sendToClientRaw.length());




                ULONG clientPendingDataLen = BIO_ctrl_pending(ioContext->networkBio);
                auto clientPendingDataBuf = new CHAR[clientPendingDataLen]{};
                BIO_read(ioContext->networkBio, clientPendingDataBuf, clientPendingDataLen);


                ioContext->wsaBuf = {
                    clientPendingDataLen,
                    clientPendingDataBuf
                };

                MYPRINT(clientPendingDataLen);

                asySend(ioContext, ioContext->socket, EventIOType::ServerIOWrite);









                break; 
            }





            default:
                break;
        }


    }


}

int SSLProxyServer::clientHelloSelectServerCTX(_In_ SSL *ssl,
                                               _In_ int *ignore,
                                               _In_ void *arg) {
    const char *servername;
    const unsigned char *p;
    size_t len, remaining;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &p,
                                   &remaining) ||
        remaining <= 2) {
        SSL_CTX_use_certificate_file(static_cast<SSL_CTX *>(arg), "cache\\www.baidu.com.crt", SSL_FILETYPE_PEM);
        auto m = SSL_CTX_use_PrivateKey_file(static_cast<SSL_CTX *>(arg), "cache\\www.baidu.com.key", SSL_FILETYPE_PEM);
        return 1;
    }
    /* Extract the length of the supplied list of names. */
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining)
        return 0;
    remaining = len;
    /*
     * The list in practice only has a single element, so we only consider
     * the first one.
     */
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return 0;
    remaining--;
    /* Now we can finally pull out the byte array with the actual hostname. */
    if (remaining <= 2)
        return 0;
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining)
        return 0;
    remaining = len;
    servername = (const char *) p;

    std::string serverHostname;
    if (servername != nullptr) {
        serverHostname.append(servername,remaining);
    }
    if (serverHostname.length() > 0) {
        auto *new_ctx = static_cast<SSL_CTX *>(arg);
        SSL_set_SSL_CTX(ssl, new_ctx);
        SSL_set_options(ssl, SSL_CTX_get_options(new_ctx));
        // 根据得到的域名来重新生成证书并指定路径
        // 维护一个线程安全的 map


        std::cout << "serverHostname = " << serverHostname << std::endl;

        std::string keyFilePath = "cache\\" + serverHostname + ".key";
        std::string certFilePath = "cache\\" + serverHostname + ".crt";
        certMtx.lock();
        if (!checkIfCertFileExists(keyFilePath) ||
            !checkIfCertFileExists(certFilePath)
                ) {

            //std::cout << keyFilePath << std::endl;
#ifdef CERT_GEN
            // 生成证书
            std::string cmdOfCert;
            cmdOfCert.append("kill-cert\\mkcert.exe -key-file ")
                    .append(keyFilePath + " ")
                    .append("-cert-file ")
                    .append(certFilePath + " ")
                    .append(serverHostname);
            std::cout << cmdOfCert << std::endl;
            ::system(cmdOfCert.c_str());
#endif // CERT_GEN


        }


        certMtx.unlock();
        SSL_use_certificate_file(ssl, certFilePath.c_str(), SSL_FILETYPE_PEM);
        auto m = SSL_use_PrivateKey_file(ssl, keyFilePath.c_str(), SSL_FILETYPE_PEM);
        assert(m == 1);
        return 1;

    }


    return 0;
}

bool SSLProxyServer::checkIfCertFileExists(const std::string &filePath) {
    {
        //std::lock_guard<std::mutex> lg(mtx);
        std::filesystem::path dir("cache"); // 该文件创建在 构建后的 DEBUG 目录中
        if (!std::filesystem::exists("cache")) {
            std::filesystem::create_directory("cache");
            return false;
        }

        std::filesystem::directory_iterator files("cache");
        for (auto& file : files) {
            if (file.path() == filePath)return true;
        }
        return false;

        // 相当于上面的判断
//        return std::any_of(begin(files), end(files),
//                           [&filePath](auto &file) {
//                               return file.path() == filePath;
//                           });

    }
}


