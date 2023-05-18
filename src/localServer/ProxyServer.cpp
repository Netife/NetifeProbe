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
        _Out_ std::string &)> &func
) : commitDataFunc(func) {

    // 初始化 Windows server api
    WSADATA wsaData;
    WORD wsaVersion = MAKEWORD(2, 2);
    if (0 != WSAStartup(
            wsaVersion,
            &wsaData)) {
        cerr << "failed to start WSA :" << GetLastError() << endl;
        exit(-1);
    }


    //  设置地址簇
    serverSocketAddr.sin_family = AF_INET;
    serverSocketAddr.sin_port = htons(proxyPort);
    serverSocketAddr.sin_addr.s_addr = INADDR_ANY;  // 监听所有本机ip


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


/*    // 配置 addr 可重用，不能重用，否则地址冲突！
    int on = 1;
    if (SOCKET_ERROR == setsockopt(serverSocketFD, SOL_SOCKET, SO_REUSEADDR,
                                   (const char *) &on, sizeof(int))) {
        closesocket(serverSocketFD);
        cerr << "failed to re-use address: " << GetLastError() << endl;
        exit(-2);
    }*/


    // 配置 io 非阻塞
    unsigned long ul = 1;
    if (SOCKET_ERROR == ioctlsocket(
            serverSocketFD,
            FIONBIO,
            &ul)) {
        perror("FAILED TO SET NONBLOCKING SOCKET");
        closesocket(serverSocketFD);
        exit(-3);
    }


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

    if (SOCKET_ERROR == ::listen(
            serverSocketFD,
            maxWaitList)) {
        cerr << "failed to listen socket: " << WSAGetLastError() << endl;
        closesocket(serverSocketFD);
        exit(-5);
    }


    // 初始化 IOCP
    hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                   nullptr,
                                   0,
                                   NumberOfThreads);
    if (INVALID_HANDLE_VALUE == hIOCP) {
        cerr << "FAILED TO CREATE IOCP HANDLE:" << WSAGetLastError() << endl;
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
    for (size_t i = 0; i < NumberOfThreads; i++) {
        threadGroup.emplace_back([this]() { eventWorkerThread(); });
    }


    // 启动工作线程
    for (auto &t: threadGroup) {
        t.detach();
    }




    for (auto i = 0;i < 100;i++){
        newAccept();
    }

/*    // 启动检测 accept 消息的线程
    acceptThread = std::thread([this]() { acceptWorkerThread(); });
    acceptThread.detach();*/


}


void ProxyServer::acceptWorkerThread() {
    while (!isShutdown) {
        // 开始监听接入
        struct sockaddr_in clientSocketAddr{};// = serverSocketAddr;
        // {};,不能重用 address，否则会出现地址冲突！
        int clientAddrLen = sizeof(clientSocketAddr);
        SOCKET clientSocket = accept(
                serverSocketFD,
                (sockaddr *) &clientSocketAddr,
                &clientAddrLen);
        if (INVALID_SOCKET == clientSocket) continue;


        unsigned long ul = 1;
        if (SOCKET_ERROR == ioctlsocket(
                clientSocket,
                FIONBIO,
                &ul)) {
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            continue;
        }

        // 将句柄和完成端口关联起来
        if (nullptr == CreateIoCompletionPort(
                (HANDLE) clientSocket,
                hIOCP,
                0,
                0)) {
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            continue;
        }


        // 开始接受请求，这里执行第一次异步接收，之后的请求处理交给工作线程来完成
        DWORD nBytes = MaxBufferSize;
        DWORD dwFlags = 0;
        auto ioContext = new IOContext;
        ioContext->buffer = new CHAR[MaxBufferSize]{};
        ioContext->wsaBuf = {MaxBufferSize, ioContext->buffer};

        ioContext->socket = clientSocket;
        ioContext->type = EventIOType::ServerIORead;
        ioContext->addr = clientSocketAddr;
        ioContext->altSocket = clientSocket;
        auto rt = WSARecv(
                clientSocket,
                &ioContext->wsaBuf,
                1,
                &nBytes, // 接收到的数据长度
                &dwFlags,
                &ioContext->overlapped,
                nullptr);
        auto err = WSAGetLastError();
        if (SOCKET_ERROR == rt && ERROR_IO_PENDING != err) {
            std::cerr << "err0 receive" << std::endl;
            // 发生不为 ERROR_IO_PENDING 的错误
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            delete ioContext;
            ioContext = nullptr;
        }

    }
}


void ProxyServer::eventWorkerThread() {
    putchar('T');
    IOContext *ioContext = nullptr;
    DWORD lpNumberOfBytesTransferred = 0;
    void *lpCompletionKey = nullptr;

    // 只是临时存储
    DWORD dwFlags = 0;
    DWORD nBytes = MaxBufferSize;

    while (true) {
        // 接收到前面 WSARecv 的 IO 完成通知
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

        puts("ininiin");
        // 没有可操作数据，但是是连接请求，需要接受！
//        if (lpNumberOfBytesTransferred == 0) continue;

        cout << ioContext->nBytes << endl;
        // 读取或者发送的字节长度，这里 += 是累计之前的所有数据
        ioContext->nBytes += lpNumberOfBytesTransferred;
        // 这里的字节数统计有问题，，，
        // 没有问题，但是没有记录最后的\0，需要手动记录上（或者说EOF？）！


        cerr << "iocp " << lpNumberOfBytesTransferred << endl;
        // 处理对应的事件
        switch (ioContext->type) {

            case EventIOType::ServerIOAccept:{
                // 继续等待新连接！
                newAccept();

                puts("come in!!!");

                auto newAddr =
                        *reinterpret_cast<sockaddr_in*>
                        (&ioContext->addresses[1]);

                WCHAR ipDotDec[20]{};
                InetNtop(AF_INET,
                         (void *) &newAddr.sin_addr,
                         ipDotDec,
                         sizeof(ipDotDec));
                std::wcout << L"new accept event: to " << ipDotDec << std::endl;



                auto clientSocket = ioContext->socket;
                // 这里执行第一次异步接收，之后的请求处理也交给工作线程来完成
                // 复用上一个 IOContext 对象，并且修改类型
                ioContext->type = EventIOType::ServerIORead;
                ioContext->buffer = new CHAR[MaxBufferSize]{};
                ioContext->wsaBuf = {MaxBufferSize, ioContext->buffer};
                ioContext->addr = newAddr;
                ioContext->altSocket = clientSocket;
                auto rtOfReceive = WSARecv(
                        clientSocket,
                        &ioContext->wsaBuf,
                        1,
                        &nBytes, // 接收到的数据长度
                        &dwFlags,
                        &ioContext->overlapped,
                        nullptr);
                auto errReceive = WSAGetLastError();
                if (SOCKET_ERROR == rtOfReceive && ERROR_IO_PENDING != errReceive) {
                    std::cerr << "err0 receive" << std::endl;
                    // 发生不为 ERROR_IO_PENDING 的错误
                    shutdown(clientSocket, SD_BOTH);
                    closesocket(clientSocket);
                    delete ioContext;
                    ioContext = nullptr;
                }



                break;
            }


            case EventIOType::ServerIORead: {

                /*****************************************************************
                 * 可能会存在缓冲区不够的问题，必须保证请求全部接受完毕才能发送!!            *
                 * 我修改 IOContext->buf 为动态分配的缓冲区，以便在这里改变尺寸           *
                 *****************************************************************/

                // 如果缓冲区满了
                if (MaxBufferSize == lpNumberOfBytesTransferred) {
                    puts("PPPPPP");

                    // 生成新的 buf
                    // 每次开辟内存 以 MaxBufferSize 为单位递增
                    auto newBuf = new CHAR[MaxBufferSize * (ioContext->seq + 1)];
                    // 相比 memcpy 不会出现内存地址重叠时拷贝覆盖的情况
                    memmove(newBuf,
                            ioContext->buffer,
                            MaxBufferSize * ioContext->seq);
                    delete[] ioContext->buffer; // 释放之前的空间
                    ioContext->buffer = newBuf; // 使用新的空间
                    ioContext->wsaBuf = { // 将要存放数据的地址范围以这里为准
                            static_cast<ULONG>(MaxBufferSize),
                            ioContext->buffer + MaxBufferSize * (ioContext->seq)
                    };
                    // 标识缓冲区扩大后的情况
                    ++ioContext->seq;

                    // 使用新的，扩大后的 IOContext 继续发送
                    auto rtOfReceive = WSARecv(
                            ioContext->socket,
                            &ioContext->wsaBuf, // 数据放在这里
                            1,
                            &nBytes, // 接收到的数据长度,不过这里不修改重叠结构，通知的时候再修改
                            &dwFlags,
                            &ioContext->overlapped,
                            nullptr);
                    auto errReceive = WSAGetLastError();
                    if (SOCKET_ERROR == rtOfReceive && ERROR_IO_PENDING != errReceive) {
                        std::cerr << "err0 receive" << std::endl;
                        // 发生不为 ERROR_IO_PENDING 的错误
                        shutdown(ioContext->socket, SD_BOTH);
                        closesocket(ioContext->socket);
                        delete ioContext;
                        ioContext = nullptr;
                    }

                    // 跳过下面的逻辑
                    continue;


                }
                // 到这里说明成功把所有请求读取完毕




                // 打印读到数据的ip
                WCHAR ipDotDec[20]{};
                InetNtop(AF_INET,
                         (void *) &ioContext->addr.sin_addr,
                         ipDotDec,
                         sizeof(ipDotDec));
                std::wcout << ipDotDec << std::endl;


                std::string originDataFromClient(ioContext->buffer, ioContext->nBytes); // TODO:看看

//                originDataFromClient.push_back('\0');
                // 这里直接初始化有坑，如果读到的数据有\0，比如接受图片，
                // \0后的数据似乎都不会被统计到，因此必须指定初始化长度！！
                // 最后加一个 \0 是因为 EOF??告知remote服务器，数据发送完毕



                ioContext->sendToServer; // 经其他模块处理后的新数据，要发送给远程服务器
                commitData(originDataFromClient,
                           0,
                           ioContext->addr.sin_addr,
                           true,
                           ioContext->sendToServer);


                // 打印修改后的数据
                puts(ioContext->sendToServer.c_str());
                fflush(stdout);



                delete[] ioContext->buffer;
                ioContext->buffer =
                        const_cast<CHAR*>(ioContext->sendToServer.c_str());

                ioContext->wsaBuf = {
                        static_cast<ULONG>(ioContext->sendToServer.length()),
                        ioContext->buffer
                };


                puts("LLL");

                // 开始请求远程服务器，依然 IOCP
                WSADATA wsaData;
                auto initWSARt = WSAStartup(MAKEWORD(2, 2), &wsaData);
                assert(0 == initWSARt);

                sockaddr_in remoteServerAddr{};
                remoteServerAddr.sin_family = AF_INET;
                remoteServerAddr.sin_port = htons(ALT_PORT);
                remoteServerAddr.sin_addr = ioContext->addr.sin_addr;
                ioContext->altSocket = ioContext->socket; // 暂存原始客户端socket

                // 这里开始 IOCP，创建新的客户端IO文件描述符
                ioContext->socket = WSASocketW(
                        AF_INET,
                        SOCK_STREAM,
                        0,
                        nullptr,
                        0,
                        WSA_FLAG_OVERLAPPED);
                if (INVALID_SOCKET == ioContext->socket) {
                    closesocket(ioContext->socket);
                    cerr << "failed to create socket: " << WSAGetLastError() << endl;
                    exit(-9);
                }



                // Connect!! TODO 有时间可以改成异步 ConnectEx
                int flag;
                flag = connect(
                        ioContext->socket,
                        (sockaddr *) &remoteServerAddr,
                        sizeof(remoteServerAddr));

                if (flag < 0) {
                    std::cerr << "connect to remote server error:" << WSAGetLastError() << std::endl;
                    exit(-11);
                    continue;
                }

                // 创建 IOCP，和完成端口关联起来
                if (nullptr == CreateIoCompletionPort(
                        (HANDLE) ioContext->socket,
                        hIOCP,
                        0,
                        0)) {
                    shutdown(ioContext->socket, SD_BOTH);
                    closesocket(ioContext->socket);
                    continue;
                }







                // IOCP 请求发送

                        // 要发的数据一定是完整的，不必担心「缓冲区」的问题

                ioContext->type = EventIOType::ClientIOWrite; // 作为客户端发送数据
                ioContext->addr = remoteServerAddr;
                auto rtOfSend = WSASend(
                        ioContext->socket,
                        &ioContext->wsaBuf,
                        1,
                        &nBytes,  // 用不上
                        dwFlags,
                        &(ioContext->overlapped),
                        nullptr);

                auto errSend = WSAGetLastError();
                if (SOCKET_ERROR == rtOfSend && errSend != WSAGetLastError()) {
                    std::cerr << "err occur when send to remove server " << WSAGetLastError() << std::endl;
                    // 返回信息发生错误
                    closesocket(ioContext->socket);
                    // buf 由 string 管理，不需要删除
                    delete ioContext;
                    ioContext = nullptr;
                    continue;
                }

                puts("CCCCCCCCCCCCDAnlg");


                // 同时准备异步接收数据
                auto newIoContext = new IOContext;
                newIoContext->buffer = new CHAR[MaxBufferSize]{};
                newIoContext->wsaBuf = {MaxBufferSize, newIoContext->buffer};

                newIoContext->socket = ioContext->socket;
                newIoContext->type = EventIOType::ClientIORead; // 代理服务器作为客户端时的读
                newIoContext->addr = ioContext->addr;
                newIoContext->altSocket = ioContext->altSocket; // 传3

                auto rtOfReceive = WSARecv(
                        newIoContext->socket,
                        &newIoContext->wsaBuf,
                        1,
                        &nBytes, // 不使用
                        &dwFlags, // 不使用
                        &newIoContext->overlapped,
                        nullptr);
                auto errReceive = WSAGetLastError();
                if (SOCKET_ERROR == rtOfReceive && ERROR_IO_PENDING != errReceive) {
                    std::cerr << "err receive data from remote server :" << WSAGetLastError() << std::endl;
                    // 发生不为 ERROR_IO_PENDING 的错误
                    shutdown(newIoContext->socket, SD_BOTH);
                    closesocket(newIoContext->socket);
                    delete[] newIoContext->buffer;
                    newIoContext->buffer = nullptr;
                    delete newIoContext;
                    newIoContext = nullptr;
                }



                // TODO: 结束
                break;
            }

            case EventIOType::ClientIOWrite: {

                // 写入远程服务器结束，善后
                ioContext->sendToServer.clear();
                // 缓冲区由 string 管理

                delete ioContext;
                ioContext = nullptr;





                break;

            }

            case EventIOType::ClientIORead: {
                // 如果缓冲区满了
                if (MaxBufferSize == lpNumberOfBytesTransferred) {

                    puts("AAAAAAAAAGFQAGHAFDH");

                    // 重新生成 IOContext


                    // 每次开辟内存 以 MaxBufferSize 为单位递增
                    auto newBuf = new CHAR[MaxBufferSize * (ioContext->seq + 1)];

                    // 相比 memcpy 不会出现内存地址重叠时拷贝覆盖的情况
                    memmove(newBuf,
                            ioContext->buffer,
                            MaxBufferSize * ioContext->seq);

                    delete[] ioContext->buffer;
                    ioContext->buffer = newBuf;
                    ioContext->wsaBuf = { // 将要存放数据的地址范围以这里为准
                            static_cast<ULONG>(MaxBufferSize),
                            ioContext->buffer + MaxBufferSize * (ioContext->seq)
                    };
                    ++ioContext->seq;


                    // 使用新的 IOContext 继续接收
                    auto rtOfReceive = WSARecv(
                            ioContext->socket,
                            &ioContext->wsaBuf, // 数据放在这里
                            1,
                            &nBytes, // 接收到的数据长度,不过这里不修改重叠结构，通知的时候再修改
                            &dwFlags,
                            &ioContext->overlapped,
                            nullptr);
                    auto errReceive = WSAGetLastError();
                    if (SOCKET_ERROR == rtOfReceive && ERROR_IO_PENDING != errReceive) {
                        std::cerr << "err0 receive" << std::endl;
                        // 发生不为 ERROR_IO_PENDING 的错误
                        shutdown(ioContext->socket, SD_BOTH);
                        closesocket(ioContext->socket);
                        delete ioContext;
                        ioContext = nullptr;
                    }

                    // 跳过下面的逻辑
                    continue;


                }


                // 到这里说明成功把所有响应读取完毕

                std::string originDataFromRemote(ioContext->buffer, ioContext->nBytes);
                originDataFromRemote.push_back('\0');


                ioContext->sendToClient; // 经其他模块处理后的新数据
                commitData(originDataFromRemote,
                           0,
                           ioContext->addr.sin_addr,
                           false, // 向内的
                           ioContext->sendToClient);


                // 打印修改后的数据
                puts(ioContext->sendToClient.c_str());
                fflush(stdout);









                // 写回客户端
                ioContext->socket = ioContext->altSocket;
                delete[] ioContext->buffer;
                ioContext->buffer =
                        const_cast<CHAR*>(ioContext->sendToClient.c_str());

                ioContext->wsaBuf = {
                        static_cast<ULONG>(ioContext->sendToClient.length()),
                        ioContext->buffer
                };

                ioContext->type = EventIOType::ServerIOWrite; // 作为客户端发送数据


                auto rtOfSend = WSASend(
                        ioContext->socket,
                        &ioContext->wsaBuf,
                        1,
                        &nBytes,  // 用不上
                        dwFlags,
                        &ioContext->overlapped,
                        nullptr);

                auto errSend = WSAGetLastError();
                if (SOCKET_ERROR == rtOfSend && errSend != WSAGetLastError()) {
                    std::cerr << "err occur when send to remove server " << WSAGetLastError() << std::endl;
                    // 返回信息发生错误
                    closesocket(ioContext->socket);
                    // buf 由 string 管理，不需要删除
                    ioContext->sendToClient.clear();
                    delete ioContext;
                    ioContext = nullptr;
                    continue;
                }


                break;
            }


            case EventIOType::ServerIOWrite: {
                // 善后
                // buf 由 string 管理，不需要删除
                ioContext->sendToClient.clear();
                delete ioContext;
                ioContext = nullptr;


                break;
            }
        }
    }
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






    // 切记，也要和iocp绑定，不然后续send recv事件没办法通知
    if (nullptr == CreateIoCompletionPort(
            (HANDLE)ioContext->socket,
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
    if (bRetVal == FALSE)
    {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING)
        {
            std::cerr << WSAGetLastError() << std::endl;
            closesocket(ioContext->socket);
            return 0;
        }
    }

    return 1;

}

