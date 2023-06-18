#include "ProxyServer.h"
#include <cassert>


using namespace std;


#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")


ProxyServer::ProxyServer(_In_ UINT proxyPort,
                         _In_ const std::function<int(
        _In_ const std::string &,
        _In_ const UINT32 &,
        _In_ const in_addr &,
        _In_ const bool &,
        _In_ const bool &,
        _Out_ std::string &)> &func
) : commitDataFunc(func) {

    // 初始化 Windows server api
    WSADATA wsaData;
    WORD wsaVersion = MAKEWORD(2, 2);
    if (0 != WSAStartup(
            wsaVersion,
            &wsaData)) {
        std::cerr << "failed to start WSA :" << GetLastError() << std::endl;
        exit(-1);
    }


    // 创建代理服务器的文件描述符，这里开始使用新的api
    serverSocketFD = WSASocketW(
            AF_INET,
            SOCK_STREAM,
            0,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED);
    if (INVALID_SOCKET == serverSocketFD) {
        closesocket(serverSocketFD);
        cerr << "failed to create socket: " << WSAGetLastError() << endl;
        exit(-2);
    }

    // 配置选项
    int on = 1;
    if (SOCKET_ERROR == setsockopt(
            serverSocketFD,
            SOL_SOCKET,  // 在套接字级别设置选项
            SO_REUSEADDR,
            (const char *) &on,
            sizeof(int))) {
        std::cerr << "failed to re-use address (%d)"
                  << GetLastError()
                  << std::endl;
        exit(-3);
    }

    //  设置地址簇
    serverSocketAddr.sin_family = AF_INET;
    serverSocketAddr.sin_port = htons(proxyPort);
    serverSocketAddr.sin_addr.s_addr = INADDR_ANY;  // 监听所有本机ip



    // 绑定
    if (SOCKET_ERROR == ::bind(
            serverSocketFD,
            (SOCKADDR *) &serverSocketAddr,
            sizeof(serverSocketAddr))) {
        cerr << "failed to bind socket: " << WSAGetLastError() << endl;
        closesocket(serverSocketFD);
        exit(-4);
    }
}

ProxyServer::~ProxyServer() {
    // 关闭代理服务器
    closesocket(serverSocketFD);


    // 关闭 accept 监听线程
    isShutdown = true;

    // 有多少个线程就发送 post 多少次，让工作线程收到事件并主动退出
    void *lpCompletionKey = nullptr;
    for (size_t i = 0; i < NumberOfThreads; i++) {
        PostQueuedCompletionStatus(hIOCP,
                                   -1,
                                   (ULONG_PTR) lpCompletionKey,
                                   nullptr);
    }

    acceptThread.join();
    for (auto &thread: threadGroup) {
        thread.join();
    }


}

void ProxyServer::startServer(_In_ int maxWaitList,
                              _Out_ std::map<UINT, UINT32> *mapPortPID
) {
    // 初始化PID传输map
    if (mapPortPID != nullptr) {
        this->mapPortWithPID = mapPortPID;
    }

    // 初始化 IOCP
    hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                   nullptr,
                                   0,
                                   0);
    if (INVALID_HANDLE_VALUE == hIOCP) {
        cerr << "FAILED TO CREATE IOCP HANDLE:" << WSAGetLastError() << endl;
        closesocket(serverSocketFD);
        exit(-6);
    }


    // 切记，先把serverSockerFD和iocp绑定，不然接收不到连接通知
    if (nullptr == CreateIoCompletionPort(
            (HANDLE) serverSocketFD,
            hIOCP,
            0,
            0)) {
        shutdown(serverSocketFD, SD_BOTH);
        closesocket(serverSocketFD);
        exit(-13);
    }

    if (SOCKET_ERROR == ::listen(
            serverSocketFD,
            maxWaitList)) {
        cerr << "failed to listen socket: " << WSAGetLastError() << endl;
        closesocket(serverSocketFD);
        exit(-5);
    }


    // 初始化工作线程
    for (size_t i = 0; i < NumberOfThreads; i++) {
        threadGroup.emplace_back([this]() { eventWorkerThread(); });
    }


    // 启动工作线程
    for (auto &t: threadGroup) {
        t.detach();
    }


    for (auto i = 0; i < 10; i++) {
        newAccept();
    }

    /*    // 启动检测 accept 消息的线程
        acceptThread = std::thread([this]() { acceptWorkerThread(); });
        acceptThread.detach();*/


}


void ProxyServer::eventWorkerThread() {
    IOContext *ioContext = nullptr;
    DWORD lpNumberOfBytesTransferred = 0;
    void *lpCompletionKey = nullptr;

    while (true) {
        // 接收到 IO 完成通知
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


        if (lpNumberOfBytesTransferred == 0) {
            switch (ioContext->type) {
                case EventIOType::ServerIOAccept:
                case EventIOType::ClientIOConnect:
                    break;
                default:
                    continue;
            }
        }


        // 读取或者发送的字节长度，这里 += 是累计之前的所有数据
//        ioContext->nBytes += lpNumberOfBytesTransferred;


/*        std::cerr << "lpNumberOfBytesTransferred = "
                  << lpNumberOfBytesTransferred
                  << std::endl;*/
        // 处理对应的事件




        switch (ioContext->type) {
            case EventIOType::ServerIOAccept: {
                // 继续等待新连接！
                newAccept();

                puts("accept finished...\n");


                auto newAddr =
                        *reinterpret_cast<sockaddr_in *>
                        (&ioContext->addresses[1]);

                WCHAR ipDotDec[20]{};
                InetNtop(AF_INET,
                         (void *) &newAddr.sin_addr,
                         ipDotDec,
                         sizeof(ipDotDec));
                std::wcout << L"new accept event: to " << ipDotDec << std::endl;

                ioContext->addr = newAddr;
                newConnect(ioContext);

                break;
            }
            case EventIOType::ClientIOConnect: {

                puts("connect finished...\n");

                // 这里执行第一次异步接收，之后的请求处理也交给工作线程来完成
                // 复用上一个 IOContext 对象，并且修改类型

                ioContext->buffer = new CHAR[MaxBufferSize]{};
                ioContext->wsaBuf = {
                        MaxBufferSize,
                        ioContext->buffer
                };

                asyReceive(ioContext,
                           ioContext->socket,
                           EventIOType::ServerIORead);


                auto newIOContext = new IOContext;
                newIOContext->remoteSocket = ioContext->remoteSocket;
                newIOContext->socket = ioContext->socket;
                newIOContext->buffer = new CHAR[MaxBufferSize]{};
                newIOContext->wsaBuf = {
                        MaxBufferSize,
                        newIOContext->buffer
                };

                asyReceive(newIOContext,
                           newIOContext->remoteSocket,
                           EventIOType::ClientIORead);


                break;
            }

            case EventIOType::ServerIORead: {


                // 到这里说明成功把所有请求读取完毕

                std::string originDataFromClient(
                        ioContext->buffer,
                        lpNumberOfBytesTransferred);

                delete[] ioContext->buffer;
                ioContext->buffer = nullptr;


                ioContext->sendToServer.clear();
                commitData(originDataFromClient,
                           0,
                           ioContext->addr.sin_addr,
                           true,
                           ioContext->sendToServer);

                // 打印修改后的数据
                for (char c: ioContext->sendToServer) {
                    putchar(c);
                }


                ioContext->wsaBuf = {
                        static_cast<ULONG>(ioContext->sendToServer.length()),
                        const_cast<CHAR *>(ioContext->sendToServer.c_str())
                };


                auto rtOfSend = asySend(ioContext,
                                        ioContext->remoteSocket,
                                        EventIOType::ClientIOWrite);


                puts("sent ....\n");


                break;
            }

            case EventIOType::ClientIORead: {
                std::string originDataFromRemote(ioContext->buffer,
                                                 lpNumberOfBytesTransferred);


                delete[] ioContext->buffer;
                ioContext->buffer = nullptr;


                ioContext->sendToClient.clear();
                commitData(originDataFromRemote,
                           0,
                           ioContext->addr.sin_addr,
                           false, // 向内的
                           ioContext->sendToClient);


                // 打印修改后的数据

/*
                for (auto c: ioContext->sendToClient) {
                    putchar(c);
                }
*/




                // 写回客户端


                ioContext->wsaBuf = {
                        static_cast<ULONG>(ioContext->sendToClient.length()),
                        const_cast<CHAR *>(ioContext->sendToClient.c_str())
                };


                asySend(ioContext,
                        ioContext->socket,
                        EventIOType::ServerIOWrite);


                break;
            }
            case EventIOType::ServerIOWrite: {
                ioContext->buffer = new CHAR[MaxBufferSize]{};
                ioContext->wsaBuf = {
                        MaxBufferSize,
                        ioContext->buffer
                };
                asyReceive(ioContext,
                           ioContext->remoteSocket,
                           EventIOType::ClientIORead);


                break;
            }
            case EventIOType::ClientIOWrite: {

                /*这个注释里面不要嵌套双斜杠！*/
                // shutdown(ioContext->socket,SD_SEND); // 终止发送

                ioContext->buffer = new CHAR[MaxBufferSize]{};
                ioContext->wsaBuf = {
                        MaxBufferSize,
                        ioContext->buffer
                };

                asyReceive(ioContext,
                        ioContext->socket,
                        EventIOType::ServerIORead);



                break;

            }


        } // end switch


    } // end while
}

int ProxyServer::commitData(_In_ const std::string &originData,
                            _In_ const UINT32 &pid,
                            _In_ const in_addr &serverAddr,
                            _In_ const bool &isOutBound,
                            _Out_ std::string &newData) {

    //    newData = originData;

    //    return 0;
    return this->commitDataFunc(originData,
                                pid,
                                serverAddr,
                                isOutBound,
                                false,
                                newData);

}

int ProxyServer::newAccept() {
    // 这里创建最初的 io上下文
    auto ioContext = new IOContext;
    ioContext->type = EventIOType::ServerIOAccept;
    //提前准备好 clientSocketFD
    ioContext->socket = WSASocket(AF_INET,
                                  SOCK_STREAM,
                                  IPPROTO_TCP,
                                  nullptr,
                                  0,
                                  WSA_FLAG_OVERLAPPED);



    setsockopt(ioContext->socket,
               SOL_SOCKET,
               SO_UPDATE_CONNECT_CONTEXT,
               nullptr,
               0);



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
    /*    std::cout << " sizeof(sockaddr_in) =" << sizeof(sockaddr_in)<<std::endl;
        std::cout << " sizeof(sockaddr_storage) =" << sizeof(sockaddr_storage)<<std::endl;*/

    int bRetVal = AcceptEx(serverSocketFD, ioContext->socket, ioContext->addresses,
                           0, addrLen, addrLen,
                           nullptr, &ioContext->overlapped);
    if (false == bRetVal) {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
            std::cerr
                    << "accept error :"
                    << WSAGetLastError()
                    << std::endl;
            closesocket(ioContext->socket);
            return -1;
        }
    }

    return 0;

}


int ProxyServer::asyReceive(_In_ IOContext *ioContext,
                            _In_ const SOCKET &socket,
                            _In_ const EventIOType &typeOfReceive) {
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
        return -1;
    }

    return 0;


}


int ProxyServer::asySend(_In_ IOContext *ioContext,
                         _In_ const SOCKET &socket,
                         _In_ const EventIOType &typeOfSend) {

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
        return -1;
    }


    return 0;
}

int ProxyServer::newConnect(_In_ BaseIOContext* baseIoContext) {
    WSADATA wsa_data;
    WORD wsa_version = MAKEWORD(2, 2);
    if (0 != WSAStartup(wsa_version, &wsa_data)) {
        std::cerr << "failed to start new WSA: "
                  << GetLastError()
                  << std::endl;
        exit(-17);
    }
    auto ioContext = reinterpret_cast<IOContext*>(baseIoContext);
    auto newAddr = ioContext->addr;

    sockaddr_in remoteServerAddr{};
    remoteServerAddr.sin_family = AF_INET;
    remoteServerAddr.sin_port = htons(ALT_PORT);
    remoteServerAddr.sin_addr = newAddr.sin_addr;

    // 这里开始 IOCP，创建新的客户端IO文件描述符，alt表示远程服务器
    ioContext->remoteSocket = WSASocketW(
            AF_INET,
            SOCK_STREAM,
            0,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED);


    if (INVALID_SOCKET == ioContext->remoteSocket) {
        closesocket(ioContext->remoteSocket);
        cerr << "failed to create socket: " << WSAGetLastError() << endl;
        exit(-9);
    }
    // Connect!! TODO 有时间可以改成异步 ConnectEx




    setsockopt(ioContext->remoteSocket,
               SOL_SOCKET,
               SO_UPDATE_CONNECT_CONTEXT,
               nullptr,
               0);



    // 和完成端口关联起来
    if (nullptr == CreateIoCompletionPort(
            (HANDLE) ioContext->remoteSocket,
            hIOCP,
            0,
            0)) {
        shutdown(ioContext->remoteSocket, SD_BOTH);
        closesocket(ioContext->remoteSocket);
        closesocket(ioContext->socket);
        assert(0);
        exit(-70);
    }


    addrinfo hints = {0};
    hints.ai_family = ioContext->addresses[1].ss_family;
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


    if (SOCKET_ERROR == ::bind(ioContext->remoteSocket,
                               pAddrInfo->ai_addr,
                               static_cast<int>(pAddrInfo->ai_addrlen))) {

    }




    ioContext->type = EventIOType::ClientIOConnect;

    // 获取connectEx指针
    if (nullptr == pfn_ConnectEx) {
        DWORD dwRetBytes = 0;
        GUID guid = WSAID_CONNECTEX;
        WSAIoctl(ioContext->remoteSocket,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 (void *) &guid,
                 sizeof(guid),
                 (void *) &pfn_ConnectEx,
                 sizeof(pfn_ConnectEx),
                 &dwRetBytes,
                 nullptr,
                 nullptr);
    }


    (*pfn_ConnectEx)(ioContext->remoteSocket,
                     (sockaddr *) &remoteServerAddr,
                     sizeof(sockaddr_in), nullptr, 0, nullptr,
                     &ioContext->overlapped);

    return 0;
}
