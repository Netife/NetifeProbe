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

        // 创建 IOCP，和完成端口关联起来
        if (nullptr == CreateIoCompletionPort(
                (HANDLE) clientSocket,
                hIOCP,
                0,
                0)) {
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            continue;
        }


        // 开始接受请求，之后的请求处理交给工作线程来完成
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
//                nBytes = ioContext->nBytes;
//                int flagOfReceive = WSARecv(
//                        ioContext->socket,
//                        &ioContext->wsaBuf,
//                        1,
//                        &nBytes,
//                        &dwFlags,
//                        &(ioContext->overlapped),
//                        nullptr);
//                auto e = WSAGetLastError();
                if (0/*SOCKET_ERROR == flagOfReceive && e != WSAGetLastError()*/) {
                    std::cerr << "err2" << std::endl;
                    // 读取发生错误
                    closesocket(ioContext->socket);
                    delete ioContext;
                    ioContext = nullptr;
                } else {
                    // 输出读取到的内容
                    // 输出读取到的内容
                    setbuf(stdout, nullptr);
                    puts(ioContext->buffer);
                    fflush(stdout);
                    //closesocket(ioContext->socket);
                    //delete ioContext;
                    //ioContext = nullptr;




                    std::cout << inet_ntoa(ioContext->addr.sin_addr) << std::endl;

                    //ZeroMemory(&ioContext->overlapped, sizeof(ioContext->overlapped));
                    //ioContext->type = IOType::Write;

                    ////puts("writing...\n");
                    //char buf[] = "hello client !!!!!";
                    //WSABUF wsaBuf = { 19,buf };

                    //DWORD nBytes2 = 0;
                    //int nRt = WSASend(
                    //	ioContext->socket,
                    //	&wsaBuf,
                    //	1,
                    //	&nBytes2,
                    //	dwFlags,
                    //	&(ioContext->overlapped),
                    //	nullptr);
                    //ioContext->type = IOType::Read;
                    WSADATA wsaData;
                    WSAStartup(MAKEWORD(2, 2), &wsaData);

                    sockaddr_in server{};
                    server.sin_family = AF_INET;
                    server.sin_port = htons(ALT_PORT);
                    server.sin_addr = ioContext->addr.sin_addr;

                    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

                    int flag;
                    flag = connect(client, (sockaddr*)&server, sizeof(server));

                    if (flag < 0) {
                        std::cerr << "error!" << std::endl;
                        //delete ioContext;
                        //ioContext = nullptr;
                        continue;
                    }

                    const CHAR* buf = ioContext->buffer;

                    std::cout << "MMM " << nBytes << std::endl;
                    for (auto i = 0; i < nBytes;)
                    {
                        auto lenOfSentPacket = send(client, buf + i, nBytes - i, 0);
                        if (lenOfSentPacket == SOCKET_ERROR)
                        {
                            std::cerr << "failed to send to socket : " << WSAGetLastError() << std::endl;
                            shutdown(ioContext->socket, SD_BOTH);
                            shutdown(client, SD_BOTH);
                            delete ioContext;
                            ioContext = nullptr;

                            return;
                        }
                        i += lenOfSentPacket;
                    }
                    std::string res;
                    char rec[1025]{};
                    while (auto lenOfRevPacket = recv(client, rec, 1024, 0)) {
                        if (lenOfRevPacket == SOCKET_ERROR)
                        {
                            std::cerr << "failed to recv from socket: " << WSAGetLastError();
                            shutdown(ioContext->socket, SD_BOTH);
                            shutdown(client, SD_BOTH);
                            delete ioContext;
                            ioContext = nullptr;
                            return;
                        }

                        //rec[lenOfRevPacket] = 0;
                        res.append(rec,lenOfRevPacket); // 大坑！！！一定要带上长度！
                    }

                    WSABUF wsaBuf = { static_cast<ULONG>(res.length()),(char*)res.c_str() };
                    DWORD nBytes2 = 0;


                    int nRt = WSASend(
                            ioContext->socket,
                            &wsaBuf,
                            1,
                            &nBytes2,
                            dwFlags,
                            &(ioContext->overlapped),
                            nullptr);

                    setbuf(stdout, nullptr);
                    puts(wsaBuf.buf);
                    fflush(stdout);


                }
                break;
            }
            case IOType::Write: {
                // 暂时没用到，这里是写回浏览器的IO操作结束后，把写回去的信息打印出来
                // TODO 后续有时间的话，尝试把阻塞式请求远程服务器的逻辑也改成 IOCP, hh

                puts(ioContext->buffer);
                fflush(stdout);

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

