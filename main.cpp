#include "ProxyServer.h"
#include "PacketDivert.h"

using namespace std;
#define PROXY_PORT 34010
#define ALT_PORT 43010
#define SERVER_PORT 80

#define GRPC_DEBUG_MODE true
#define DEBUG_DISPATCHER_HOST "localhost"
#define DEBUG_DISPATCHER_PORT "7890"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

static map<UINT, UINT32> mapPortPID;
int main()
{
	::system("chcp 65001");
//	char filter[256]{};
	UINT16 serverPort = SERVER_PORT, proxyPort = PROXY_PORT, altPort = ALT_PORT;
//	snprintf(filter, sizeof(filter),
//			 "tcp and "
//			 "(tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or "
//			 "tcp.SrcPort == %d or tcp.SrcPort == %d or tcp.SrcPort == %d) "
//             "and (ip.SrcAddr == 216.127.185.51 or ip.DstAddr == 216.127.185.51) ",
//			 serverPort, proxyPort, altPort, serverPort, proxyPort, altPort);

	auto dealFunc = [&](PWINDIVERT_IPHDR &ipHeader, PWINDIVERT_TCPHDR &tcpHeader, WINDIVERT_ADDRESS &addr)
	{

		if (addr.Outbound) // 向外部主机发送的数据包
		{
			if (tcpHeader->DstPort == htons(serverPort))
			{
				// Reflect: PORT ---> PROXY

				tcpHeader->DstPort = htons(proxyPort);
				swap(ipHeader->SrcAddr, ipHeader->DstAddr);
				addr.Outbound = FALSE;
			}
			else if (tcpHeader->SrcPort == htons(proxyPort))
			{
				// Reflect: PROXY ---> PORT

				tcpHeader->SrcPort = htons(serverPort);
				swap(ipHeader->SrcAddr, ipHeader->DstAddr);
				addr.Outbound = FALSE;
			}
			else if (tcpHeader->DstPort == htons(altPort))
			{
				// Redirect: ALT ---> PORT

				tcpHeader->DstPort = htons(serverPort);
			}
		}
		else
		{
			if (tcpHeader->SrcPort == htons(serverPort))
			{
				// Redirect: PORT ---> ALT

				tcpHeader->SrcPort = htons(altPort);
			}
		}
	};

    // 这个地方来判断是否启用了DEBUG模式，如果启用了那么就使用DEFINE的HOST和PORT

    //TODO 这个地方需要修改！为了不侵入本REPO程序故没有修改启动逻辑


	ProxyServer proxyServer(proxyPort, DEBUG_DISPATCHER_HOST, DEBUG_DISPATCHER_PORT);
	PacketDivert packetDivert("tcp");
    PacketDivert sniffDivert("tcp and localPort", WINDIVERT_LAYER_FLOW,
                             WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

	bool one = false;
	bool two = false;
	bool three = false;
	thread([&]()->void {
		proxyServer.startServer(256, altPort,&mapPortPID); // TODO 魔法值
		one = true;
    }).detach();

	thread([&]()->void {
		packetDivert.startDivert(dealFunc);
		two = true;
    }).detach();

	thread([&]()->void {
        // new 的写法似乎存在内存泄漏问题，使用智能指针要解决生命周期问题，还是先创建对象吧
		sniffDivert.startDivert([](WINDIVERT_ADDRESS) {},&mapPortPID);
		three = true;
    }).detach();

	while (one == false || two == false || three == false)
	{

//		for (auto elem : mapPortPID)
//		{
			//			cout << elem.first << "->"<<elem.second <<endl;
//		}
		Sleep(5000);
	}

	return 0;
}