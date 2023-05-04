#include "ProxyServer.h"
#include <map>
using namespace std;
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

ProxyServer::ProxyServer(UINT proxyPort)
{

	// 构建 windows server api
	WSADATA wsaData;
	WORD wsaVersion = MAKEWORD(2, 2);
	// SOCKET serverSocketFD;
	if (WSAStartup(wsaVersion, &wsaData) != 0)
	{
		cerr << "failed to start WSA :" << GetLastError() << endl;
	}

	// 创建代理服务器的文件描述符
	serverSocketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocketFD == INVALID_SOCKET)
	{
		cerr << "failed to create socket: " << WSAGetLastError() << endl;
	}

	// 配置
	int on = 1;
	if (setsockopt(serverSocketFD, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(int)) == SOCKET_ERROR)
	{
		cerr << "failed to re-use address: " << GetLastError() << endl;
	}

	// struct sockaddr_in serverSocketAddr{};
	//  设置地址簇
	serverSocketAddr.sin_family = AF_INET;
	serverSocketAddr.sin_port = htons(proxyPort);

	// 绑定
	if (bind(serverSocketFD, (SOCKADDR *)&serverSocketAddr, sizeof(serverSocketAddr)) == SOCKET_ERROR)
	{
		cerr << "failed to bind socket: " << WSAGetLastError() << endl;
	}
}

ProxyServer::~ProxyServer()
{
	// 关闭代理服务器
	closesocket(serverSocketFD);
	cout << "endl" << endl;
}

void ProxyServer::startServer(int maxWaitList, UINT altPort,
							  std::map<UINT, UINT32> *mapPortPID)
{
	if (mapPortPID != nullptr)
	{
		this->mapPortWithPID = mapPortPID;
	}

	if (listen(serverSocketFD, maxWaitList) == SOCKET_ERROR)
	{
		cerr << "failed to listen socket: " << WSAGetLastError() << endl;
	}

	isLoop = true;
	while (isLoop)
	{
		// Wait for a new connection.

		cout << "server port: " << ntohs(serverSocketAddr.sin_port) << endl
			 << endl;
		struct sockaddr_in clientSocketAddr
		{
		}; // = serverSocketAddr; // 连接代理服务器的socket，但是是被修改后的
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
//				memset(&fakerServerSocketAddr, 0, sizeof(fakerServerSocketAddr));

				fakerServerSocketAddr.sin_family = AF_INET;
				fakerServerSocketAddr.sin_port = htons(altPort);
				fakerServerSocketAddr.sin_addr = clientSocketAddr.sin_addr; // 重定向后其实就是真实服务器ip

				if (connect(newClientSocketFD, (SOCKADDR*)&fakerServerSocketAddr, sizeof(fakerServerSocketAddr)) == SOCKET_ERROR)
				{
					cerr << "failed to connect socket: " << WSAGetLastError() << endl;
					closesocket(clientSocketFD);
					closesocket(newClientSocketFD);
					return;
				}

				// 新客户端与remote服务器的连接建立后，异步传输数据：


				bool isFinished = false;
				thread([=, &isFinished]()->void {
					transDataInner(clientSocketFD, newClientSocketFD, false,originClientPort,
                                   fakerServerSocketAddr.sin_addr);
					// 向外的数据包

					isFinished = true;
					// 线程结束
					}).detach();
					transDataInner(newClientSocketFD, clientSocketFD, true,originClientPort,
                                   fakerServerSocketAddr.sin_addr);
					// 向里的数据包

					while (!isFinished) {
						Sleep(100);
					}
					closesocket(clientSocketFD);
					closesocket(newClientSocketFD); })
			.detach();
	}
}

int ProxyServer::transDataInner(SOCKET getDataSocketFD, SOCKET sendDataSocketFD,
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
}

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
	cout << "remote server ip is: "
		 << (int)serverIp.s_b1 << "."
		 << (int)serverIp.s_b2 << "."
		 << (int)serverIp.s_b3 << "."
		 << (int)serverIp.s_b4 << "\t"
		 << endl;

	cout << "local application pid is: " << pid << endl;
	*lenOfNewData = lenOfOriData;
	*newData = new char[*lenOfNewData]{};
	for (auto i = 0; i < *lenOfNewData; i++)
	{
		(*newData)[i] = originData[i];
		if ((*newData)[i] == 'M')
			(*newData)[i] = 'F';
	}
	return 0;
}
