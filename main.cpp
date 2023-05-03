#include "ProxyServer.h"
#include "PacketDivert.h"


using namespace std;
#define PROXY_PORT 34010
#define ALT_PORT 43010
#define SERVER_PORT 80
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"shlwapi.lib")


static map<UINT,UINT32> mapPortPID;
int main()
{
    ::system("chcp 65001");
	char filter[256]{};
	UINT16 serverPort = SERVER_PORT, proxyPort = PROXY_PORT, altPort = ALT_PORT;
	snprintf(filter, sizeof(filter),
		"tcp and "
		"(tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or "
		"tcp.SrcPort == %d or tcp.SrcPort == %d or tcp.SrcPort == %d) and (ip.SrcAddr == 216.127.185.51 or ip.DstAddr == 216.127.185.51) ",
		serverPort, proxyPort, altPort, serverPort, proxyPort, altPort);





	auto dealFunc = [&](PWINDIVERT_IPHDR& ipHeader, PWINDIVERT_TCPHDR& tcpHeader, WINDIVERT_ADDRESS& addr) {
//        if(addr.Impostor){
//            printf("**************");
//        }

		if (addr.Outbound) // 向外部主机发送的数据包
		{
			if (tcpHeader->DstPort == htons(serverPort))
			{
//				cout << "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n" << ntohs(tcpHeader->SrcPort) <<endl;
				// Reflect: PORT ---> PROXY
//				UINT32 oriDstAddr = ipHeader->DstAddr;
				tcpHeader->DstPort = htons(proxyPort);
//				ipHeader->DstAddr = ipHeader->SrcAddr;
//				ipHeader->SrcAddr = oriDstAddr;


                cout << "tcpHeader->SrcPort: "<< tcpHeader->SrcPort<<endl;
                swap(ipHeader->SrcAddr,ipHeader->DstAddr);
				addr.Outbound = FALSE;
			}
			else if (tcpHeader->SrcPort == htons(proxyPort))
			{
				// Reflect: PROXY ---> PORT
//				UINT32 oriDstAddr = ipHeader->DstAddr;
				tcpHeader->SrcPort = htons(serverPort);
//				ipHeader->DstAddr = ipHeader->SrcAddr;
//				ipHeader->SrcAddr = oriDstAddr;


                swap(ipHeader->SrcAddr,ipHeader->DstAddr);


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



	auto dealFunc2 = [&](PWINDIVERT_IPHDR ipHeader, PWINDIVERT_TCPHDR tcpHeader, WINDIVERT_ADDRESS addr) {
		cout << "tarport####:  ->" << tcpHeader->DstPort << endl;
	};







	ProxyServer proxyServer(proxyPort);
	PacketDivert packetDivert(filter);
	

	bool one = false;
	bool two = false;
	bool three = false;
	thread([&]() {
		proxyServer.startServer(16, altPort,&mapPortPID);
		one = true;
	}).detach();

	thread([&]() {
		packetDivert.startDivert(dealFunc);
		two = true;
	}).detach();

	thread([&]() {
		(new PacketDivert("tcp and localPort", WINDIVERT_LAYER_FLOW, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY))->startDivert([](WINDIVERT_ADDRESS) {},&mapPortPID);
		three = true;
		}).detach();

	while (one == false || two == false || three == false) {

		
		for (auto elem:mapPortPID){
//			cout << elem.first << "->"<<elem.second <<endl;
		}
		Sleep(5000);
	}

	return 0;




}