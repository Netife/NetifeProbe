#include "ProxyServer.h"
#include <map>
using namespace std;

#include <grpcpp/security/credentials.h>
#include <grpcpp/create_channel.h>

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

ProxyServer::ProxyServer(UINT proxyPort, const string& name, const std::string& port) : client(
        grpc::CreateChannel(name + ":" + port, grpc::InsecureChannelCredentials()))
{

	// 初始化 Windows server api
	WSADATA wsaData;
	WORD wsaVersion = MAKEWORD(2, 2);
	if (WSAStartup(wsaVersion, &wsaData) != 0)
	{
		cerr << "failed to start WSA :" << GetLastError() << endl;
	}
    //  设置地址簇
    serverSocketAddr.sin_family = AF_INET;
    serverSocketAddr.sin_port = htons(proxyPort);
    serverSocketAddr.sin_addr.s_addr = INADDR_ANY;  // 监听所有本机ip


	// 创建代理服务器的文件描述符，这里开始使用新的api
	serverSocketFD =  WSASocketW(AF_INET, SOCK_STREAM, 0,
                                 nullptr, 0, WSA_FLAG_OVERLAPPED);
	if (serverSocketFD == INVALID_SOCKET)
	{
        closesocket(serverSocketFD);
		cerr << "failed to create socket: " << WSAGetLastError() << endl;
        exit(-1);
	}

	// 配置 addr 可重用
	int on = 1;
	if (setsockopt(serverSocketFD, SOL_SOCKET, SO_REUSEADDR,
                   (const char *)&on, sizeof(int)) == SOCKET_ERROR)
	{
        closesocket(serverSocketFD);
		cerr << "failed to re-use address: " << GetLastError() << endl;
        exit(-2);
	}

    unsigned long ul = 1;
    if (SOCKET_ERROR == ioctlsocket(serverSocketFD, FIONBIO, &ul)) {
        perror("FAILED TO SET NONBLOCKING SOCKET");
        closesocket(serverSocketFD);
        exit(-3);
    }


	// 绑定
	if (::bind(serverSocketFD,
               (SOCKADDR *)&serverSocketAddr,
               sizeof(serverSocketAddr)) == SOCKET_ERROR)
	{
		cerr << "failed to bind socket: " << WSAGetLastError() << endl;
        closesocket(serverSocketFD);
        exit(-4);
	}
}

ProxyServer::~ProxyServer()
{
	// 关闭代理服务器
	closesocket(serverSocketFD);
	cout << "endl" << endl;
}

void ProxyServer::startServer(int maxWaitList,
							  std::map<UINT, UINT32> *mapPortPID)
{
	if (mapPortPID != nullptr)
	{
		this->mapPortWithPID = mapPortPID;
	}

	if (::listen(serverSocketFD, maxWaitList) == SOCKET_ERROR)
	{
		cerr << "failed to listen socket: " << WSAGetLastError() << endl;
        closesocket(serverSocketFD);
        exit(-5);
	}


    // 初始化 IOCP
    hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                   nullptr, 0, NumberOfThreads);
    if (INVALID_HANDLE_VALUE == hIOCP) {
        perror("FAILED TO CREATE IOCP HANDLE");
        closesocket(serverSocketFD);
        exit(-6);
    }
    // 初始化工作线程
    for (size_t i = 0; i < NumberOfThreads; i++) {
        threadGroup.emplace_back([this](){EventWorkerThread();});
    }

    for (auto&t : threadGroup){
        t.detach();
    }

    void* lpCompletionKey = nullptr;
    auto acceptThread = std::thread([this](){AcceptWorkerThread();});
    acceptThread.detach();

	/*while (isLoop)
	{
		// Wait for a new connection.

		cout << "server port: " << ntohs(serverSocketAddr.sin_port) << endl
			 << endl;
		struct sockaddr_in& clientSocketAddr = serverSocketAddr; // 连接代理服务器的socket，但是是被修改后的，重用socket
		int clientAddrLen = sizeof(serverSocketAddr);

		SOCKET clientSocketFD = accept(serverSocketFD, (SOCKADDR *)&clientSocketAddr, &clientAddrLen);

		auto clientIp = clientSocketAddr.sin_addr.S_un.S_un_b;
		cout << "与ProxyServer建立连接的客户端: "
			 << (int)clientIp.s_b1 << "."
			 << (int)clientIp.s_b2 << "."
			 << (int)clientIp.s_b3 << "."
			 << (int)clientIp.s_b4 << ":"
			 << ntohs(clientSocketAddr.sin_port)
			 << endl;
		UINT originClientPort = ntohs(clientSocketAddr.sin_port);

		// 由于重定向，这里ip应当是remote服务器的ip

		if (clientSocketFD == INVALID_SOCKET)
		{
			cerr << "failed to accept socket: " << WSAGetLastError() << endl;
			continue;
		}

		// 异步处理连接请求 =>
		// 将原本被抓软件（浏览器）的tcp请求，改成新开的、与remote服务器的socket连接：
		thread([&]() -> void
			   {
				// 新建一个临时的客户端
				SOCKET newClientSocketFD = socket(AF_INET, SOCK_STREAM, 0);
				if (newClientSocketFD == INVALID_SOCKET)
				{
					cerr << "failed to create socket (%d)" << WSAGetLastError() << endl;
					closesocket(clientSocketFD);
				}

				// 配置服务器端属性，这里和目标服务器位置不同，但可以通过WinDivert重定向


				struct sockaddr_in fakerServerSocketAddr{};


                //memset(&fakerServerSocketAddr, 0, sizeof(fakerServerSocketAddr));

				fakerServerSocketAddr.sin_family = AF_INET;
				fakerServerSocketAddr.sin_port = htons(altPort);
				fakerServerSocketAddr.sin_addr = clientSocketAddr.sin_addr; // 重定向后其实就是真实服务器ip

				if (connect(newClientSocketFD, (SOCKADDR*)&fakerServerSocketAddr,
                            sizeof(fakerServerSocketAddr))
                            == SOCKET_ERROR)
				{
					cerr << "failed to connect socket: " << WSAGetLastError() << endl;
					closesocket(clientSocketFD);
					closesocket(newClientSocketFD);
					return;
				}

				// 新客户端与remote服务器的连接建立后，异步传输数据：


				bool isFinished = false;
				thread([=, &isFinished]()->void {
					transDataInner(clientSocketFD,newClientSocketFD,
                                   false,originClientPort,
                                   fakerServerSocketAddr.sin_addr);
					// 向外的数据包


                    isFinished = true;


                    // 线程结束


                    }).detach();
					transDataInner(newClientSocketFD,
                                   clientSocketFD,true,originClientPort,fakerServerSocketAddr.sin_addr);


                    // 向里的数据包

					while (!isFinished) {
						Sleep(100);
					}
					closesocket(clientSocketFD);
					closesocket(newClientSocketFD); })
			.detach();
	}*/
}

void ProxyServer::AcceptWorkerThread() {
    while (!isShutdown) {
        // 开始监听接入
        struct sockaddr_in clientSocketAddr {};
        int clientAddrLen = sizeof(clientSocketAddr);
        SOCKET clientSocket = accept(serverSocketFD, (sockaddr*)&clientSocketAddr, &clientAddrLen);
        if (INVALID_SOCKET == clientSocket) continue;

        unsigned long ul = 1;
        if (SOCKET_ERROR == ioctlsocket(clientSocket, FIONBIO, &ul)) {
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            continue;
        }

        if (nullptr == CreateIoCompletionPort((HANDLE)clientSocket, hIOCP, 0, 0)) {
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            continue;
        }

        DWORD nBytes = MaxBufferSize;
        DWORD dwFlags = 0;
        auto ioContext = new IOContext;
        ioContext->socket = clientSocket;
        ioContext->type = IOType::Read;
        ioContext->addr = clientSocketAddr;
        auto rt = WSARecv(clientSocket, &ioContext->wsaBuf, 1, &nBytes, &dwFlags, &ioContext->overlapped, nullptr);
        auto err = WSAGetLastError();
        if (SOCKET_ERROR == rt && ERROR_IO_PENDING != err) {
            std::cerr << "err1" << std::endl;
            // 发生不为 ERROR_IO_PENDING 的错误
            shutdown(clientSocket, SD_BOTH);
            closesocket(clientSocket);
            delete ioContext;
            ioContext = nullptr;
        }




    }
}

void ProxyServer::EventWorkerThread() {
    putchar('A');
    IOContext* ioContext = nullptr;
    DWORD lpNumberOfBytesTransferred = 0;
    void* lpCompletionKey = nullptr;

    DWORD dwFlags = 0;
    DWORD nBytes = MaxBufferSize;

    while (true) {
        BOOL bRt = GetQueuedCompletionStatus(
                hIOCP,
                &lpNumberOfBytesTransferred,
                (PULONG_PTR)&lpCompletionKey,
                (LPOVERLAPPED*)&ioContext,
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
                int nRt = WSARecv(
                        ioContext->socket,
                        &ioContext->wsaBuf,
                        1,
                        &nBytes,
                        &dwFlags,
                        &(ioContext->overlapped),
                        nullptr);
                auto e = WSAGetLastError();
                if (SOCKET_ERROR == nRt && e != WSAGetLastError()) {
                    std::cerr << "err2" << std::endl;
                    // 读取发生错误
                    closesocket(ioContext->socket);
                    delete ioContext;
                    ioContext = nullptr;
                }
                else {
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

                        rec[lenOfRevPacket] = 0;
                        res.append(rec);
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

/*int ProxyServer::transDataInner(SOCKET getDataSocketFD, SOCKET sendDataSocketFD,
								BOOL inbound, UINT oriClientPort, struct in_addr serverAddr)
{

	UINT32 curPID = 0;


	//    cout << " originClientPort = "<<oriClientPort <<endl;

	int count = 0;
	if (mapPortWithPID != nullptr)
	{


        // 必须得找到pid！！！


		while (true)
		{
			if (mapPortWithPID->find(oriClientPort) != mapPortWithPID->end())
			{
				curPID = (*mapPortWithPID)[oriClientPort];
				break;
			}

			if (count > 30)
			{
				cerr << "can not get pid!!" << endl;
				// exit(-1);
				break;
			}
			count++;
			Sleep(100);
		}
	}

	char buf[8192];
	int lenOfRevPacket, lenOfSentPacket;

	while (true)
	{
		// Read data
		lenOfRevPacket = recv(getDataSocketFD, buf, sizeof(buf), 0);
		if (lenOfRevPacket == SOCKET_ERROR)
		{
			cerr << "failed to recv from socket: " << WSAGetLastError();
			shutdown(getDataSocketFD, SD_BOTH);
			shutdown(sendDataSocketFD, SD_BOTH);
			return -1;
		}
		if (lenOfRevPacket == 0)
		{
			shutdown(getDataSocketFD, SD_RECEIVE);
			shutdown(sendDataSocketFD, SD_SEND);
			return 0;
		}

		// 打印到控制台：
		// HANDLE console;
		//// Dump stream information to the screen.
		// console = GetStdHandle(STD_OUTPUT_HANDLE);
		// myThreadMutex.lock();
		// printf("[%.4d] \n", lenOfRevPacket);
		// SetConsoleTextAttribute(console,
		//	(inbound ? FOREGROUND_RED : FOREGROUND_GREEN)); // 入红出绿
		// for (auto i = 0; i < lenOfRevPacket; i++)
		//{
		//	putchar(buf[i]);
		// }
		// SetConsoleTextAttribute(console,
		//	FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		// myThreadMutex.unlock();

		size_t lenOfNewData = 0;
		char *newDataBuf = nullptr;
		// 引用表示传入的值是会被修改的
		commitData(buf, lenOfRevPacket, curPID, serverAddr, &newDataBuf, &lenOfNewData);

		// for (auto i = 0; i < lenOfRevPacket; i++)
		//{
		//	putchar(newDataBuf[i]);
		// }

		// Send data.分批发送
		for (auto i = 0; i < lenOfNewData;)
		{
			lenOfSentPacket = send(sendDataSocketFD, newDataBuf + i, lenOfNewData - i, 0);
			if (lenOfSentPacket == SOCKET_ERROR)
			{
				cerr << "failed to send to socket : " << WSAGetLastError() << endl;
				shutdown(getDataSocketFD, SD_BOTH);
				shutdown(sendDataSocketFD, SD_BOTH);
				return -2;
			}
			i += lenOfSentPacket;
		}
		if (newDataBuf != nullptr)
		{
			delete[] newDataBuf;
			newDataBuf = nullptr;
		}
	}

	return 0;
}*/

/// @brief 提交数据给其他模块，供扩展
/// @param originData 原始数据
/// @param lenOfOriData 原始数据长度
/// @param newData 新数据（修改）
/// @param lenOfNewData 新数据长度（修改）
/// @param pid pid
/// @return 状态
int ProxyServer::commitData(const char *const originData, const size_t lenOfOriData,
							const UINT32 pid, struct in_addr serverAddr,
							char **newData, size_t *lenOfNewData)
{

	auto serverIp = serverAddr.S_un.S_un_b;
//    bool isTar = (int)serverIp.s_b1 == 216&&
//                 (int)serverIp.s_b2 == 127&&
//                 (int)serverIp.s_b3 == 185&&
//                 (int)serverIp.s_b4 == 51;

    cout << "local application pid is: " << pid << endl;
//    *lenOfNewData = lenOfOriData;
//    *newData = new char[*lenOfNewData]{};
//    for (auto i = 0; i < *lenOfNewData; i++)
//    {
//        (*newData)[i] = originData[i];
//        if ((*newData)[i] == 'M'&&isTar)
//            (*newData)[i] = 'F';
//    }
//    return 0;

    NetifeProbeRequest netifeProbeRequest;

    //TODO 添加 uuid

    netifeProbeRequest.set_uuid("this_is_uuid");

    //添加 originDqta
    std::string rawText;

    rawText.assign(originData, originData + lenOfOriData);
    netifeProbeRequest.set_raw_text(rawText);
    netifeProbeRequest.set_pid(to_string(pid));

    //TODO 支持端口修改

    netifeProbeRequest.set_dst_ip_addr(to_string((int)serverIp.s_b1) + "." + to_string((int)serverIp.s_b2) + "." +
                                               to_string((int)serverIp.s_b3) + "." + to_string((int)serverIp.s_b4));
    netifeProbeRequest.set_protocol(NetifeMessage::NetifeProbeRequest_Protocol_TCP);

    //TODO 支持SERVER修改

    netifeProbeRequest.set_application_type(NetifeMessage::NetifeProbeRequest_ApplicationType_CLIENT);

    auto response = client.ProcessProbe(netifeProbeRequest);

    if(!response.has_value()){
        // TODO 改成错误码

        *lenOfNewData = lenOfOriData;
        *newData = new char[*lenOfNewData]{};
        for (auto i = 0; i < *lenOfNewData; i++)
        {
            (*newData)[i] = originData[i];
        }
        return 0;
    }else{
        *lenOfNewData = response.value().response_text().length();
        *newData = new char[*lenOfNewData]{};
        for (int i = 0; i < *lenOfNewData; ++i) {
            (*newData)[i] = response.value().response_text()[i];
        }

        return 0;
    }



}

