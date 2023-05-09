#include "ProxyServer.h"


using namespace std;


#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")


ProxyServer::ProxyServer(_In_ UINT proxyPort,
                         _In_ const std::function<int(
                                 _In_ const std::string &,
                                 _In_ const UINT32 &,
                                 _In_ const in_addr &,
                                 _In_ const bool &,
                                 _Out_ std::string &)>& func
                                 ):commitDataFunc(func){

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
        exit(-1);
    }


/*    // 配置 addr 可重用，不能重用，否则地址冲突！
    int on = 1;
    if (SOCKET_ERROR == setsockopt(serverSocketFD, SOL_SOCKET, SO_REUSEADDR,
                                   (const char *) &on, sizeof(int))) {
        closesocket(serverSocketFD);
        cerr << "failed to re-use address: " << GetLastError() << endl;
        exit(-2);
    }*/


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


    // 依此关闭所有工作线程
    isShutdown = true;

    // 有多少个线程就发送 post 多少次，让工作线程收到事件并主动退出
    void* lpCompletionKey = nullptr;
    for (size_t i = 0; i < NumberOfThreads; i++) {
        PostQueuedCompletionStatus(hIOCP, -1, (ULONG_PTR)lpCompletionKey, nullptr);
    }

    acceptThread.join();
    for (auto& thread : threadGroup) {
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


    // 初始化工作线程
    for (size_t i = 0; i < NumberOfThreads; i++) {
        threadGroup.emplace_back([this]() { eventWorkerThread(); });
    }


    // 启动工作线程
    for (auto &t: threadGroup) {
        t.detach();
    }


    // 启动检测 accept 消息的线程
    acceptThread = std::thread([this]() { acceptWorkerThread(); });
    acceptThread.detach();


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

        // 创建 IOCP
        if (nullptr == CreateIoCompletionPort(
                (HANDLE) clientSocket,
                hIOCP,
                0,
                0)) {
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            continue;
        }


        // 处理请求
        DWORD nBytes = MaxBufferSize;
        DWORD dwFlags = 0;
        auto ioContext = new IOContext();
        ioContext->socket = clientSocket;
        ioContext->type = IOType::Read;
        ioContext->addr = clientSocketAddr;
        auto rt = WSARecv(
                clientSocket,
                &ioContext->wsaBuf,
                1,
                &nBytes,
                &dwFlags,
                &ioContext->overlapped,
                nullptr);
        auto err = WSAGetLastError();
        if (SOCKET_ERROR == rt && ERROR_IO_PENDING != err) {
            std::cerr << "err0" << std::endl;
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

    DWORD dwFlags = 0;
    DWORD nBytes = MaxBufferSize;

    while (true) {
        BOOL bRt = GetQueuedCompletionStatus(
                hIOCP,
                &lpNumberOfBytesTransferred,
                (PULONG_PTR) &lpCompletionKey,
                (LPOVERLAPPED *) &ioContext,
                INFINITE);

        if (!bRt) continue;
        puts("..........1");
        // 收到 PostQueuedCompletionStatus 发出的退出指令
        if (lpNumberOfBytesTransferred == -1) break;

        if (lpNumberOfBytesTransferred == 0) continue;

        // 读到，或者写入的字节总数
        ioContext->nBytes = lpNumberOfBytesTransferred;
        // 处理对应的事件
        switch (ioContext->type) {
            case IOType::Read: {
                int flagOfReceive = WSARecv(
                        ioContext->socket,
                        &ioContext->wsaBuf,
                        1,
                        &nBytes,
                        &dwFlags,
                        &(ioContext->overlapped),
                        nullptr);
                auto e = WSAGetLastError();
                if (SOCKET_ERROR == flagOfReceive && e != WSAGetLastError()) {
                    std::cerr << "err2" << std::endl;
                    // 读取发生错误
                    closesocket(ioContext->socket);
                    delete ioContext;
                    ioContext = nullptr;
                } else {
                    // 输出读取到的内容
//                    setbuf(stdout, nullptr);
//                    puts(ioContext->buffer);
//                    fflush(stdout);
                    //closesocket(ioContext->socket);
                    //delete ioContext;
                    //ioContext = nullptr;


                    // 打印读到数据的ip
                    WCHAR ipDotDec[20]{};
                    InetNtop(AF_INET,
                             (void *) &ioContext->addr.sin_addr,
                             ipDotDec,
                             sizeof(ipDotDec));
                    std::wcout << ipDotDec << std::endl;



                    std::string originData = ioContext->buffer;
                    puts(originData.c_str());
                    fflush(stdout);


                    std::string newData;
                    commitData(originData,
                               0,
                               ioContext->addr.sin_addr,
                               true,
                               newData);


//                    puts(newData.c_str());
//                    fflush(stdout);


                    // 请求远程服务器
                    WSADATA wsaData;
                    WSAStartup(MAKEWORD(2, 2), &wsaData);


                    sockaddr_in server{};
                    server.sin_family = AF_INET;
                    server.sin_port = htons(ALT_PORT);
                    server.sin_addr = ioContext->addr.sin_addr;

                    SOCKET remoteServerSocketFD = socket(
                            AF_INET,
                            SOCK_STREAM,
                            IPPROTO_TCP);

                    int flag;
                    flag = connect(
                            remoteServerSocketFD,
                            (sockaddr *) &server,
                            sizeof(server));

                    if (flag < 0) {
                        std::cerr << "error!" << std::endl;
                        //delete ioContext;
                        //ioContext = nullptr;
                        continue;
                    }

                    for (auto i = 0; i < nBytes;) {
                        auto lenOfSentPacket = send(
                                remoteServerSocketFD,
                                newData.c_str() + i,
                                static_cast<int>(newData.length() - i),
                                0);
                        if (SOCKET_ERROR == lenOfSentPacket) {
                            std::cerr << "failed to send to socket : " << WSAGetLastError() << std::endl;
                            shutdown(ioContext->socket, SD_BOTH);
                            shutdown(remoteServerSocketFD, SD_BOTH);
/*                            delete ioContext;
                            ioContext = nullptr;*/

                            continue;
                        }
                        i += lenOfSentPacket;
                    }


                    // 接受remote服务器的消息
                    std::string resOriginData;
                    char recFromRemote[1025]{};
                    while (auto lenOfRevPacket = recv(
                            remoteServerSocketFD,
                            recFromRemote,
                            1024,
                            0)) {
                        if (SOCKET_ERROR == lenOfRevPacket) {
                            std::cerr << "failed to recv from socket: " << WSAGetLastError();
                            shutdown(ioContext->socket, SD_BOTH);
                            shutdown(remoteServerSocketFD, SD_BOTH);
/*                            delete ioContext;
                            ioContext = nullptr;*/
                            continue;
                        }

                        recFromRemote[lenOfRevPacket] = 0;
                        resOriginData.append(recFromRemote);
                    }

                    puts(resOriginData.c_str());
                    fflush(stdout);


                    newData.clear();
                    commitData(resOriginData,
                               0,
                               ioContext->addr.sin_addr,
                               false,
                               newData);

                    WSABUF wsaSendBuf = {
                            static_cast<ULONG>(newData.length()),
                            (char *) newData.c_str()};
                    DWORD nSentBytes = 0;



                    // 回复给客户端
                    auto flagOfSend = WSASend(
                            ioContext->socket,
                            &wsaSendBuf,
                            1,
                            &nSentBytes,
                            dwFlags,
                            &(ioContext->overlapped),
                            nullptr);

                    auto err = WSAGetLastError();
                    if (SOCKET_ERROR == flagOfSend && err != WSAGetLastError()) {
                        std::cerr << "err2send" << std::endl;
                        // 返回信息发生错误
                        closesocket(ioContext->socket);
                        delete ioContext;
                        ioContext = nullptr;
                        continue;
                    }

//                    setbuf(stdout, nullptr);
                    puts(wsaSendBuf.buf);
                    fflush(stdout);


                    //closesocket(ioContext->socket);
                    //delete ioContext;
                    //ioContext = nullptr;
                }
                break;
            }
            case IOType::Write: {
                // 暂时没用到
                break;
            }
        }
    }
}

int ProxyServer::commitData(_In_ const std::string& originData,
                            _In_ const UINT32& pid,
                            _In_ const in_addr& serverAddr,
                            _In_ const bool& isOutBound,
                            _Out_ std::string &newData) {

    newData = originData;

    return 0;
    return this->commitDataFunc(originData,
                         pid,
                         serverAddr,
                         isOutBound,
                         newData);
}

