#include "PacketDivert.h"
#include <vector>

using namespace std;
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")


#define MAX_FLOWS 256
PacketDivert::PacketDivert(const char* packetFilter, WINDIVERT_LAYER filterLayer, UINT64 modeFlag) :packetFilter(packetFilter), filterLayer(filterLayer), modeFlag(modeFlag) {}



PacketDivert::~PacketDivert()
{
	if (handle != INVALID_HANDLE_VALUE)
	{
		WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
		WinDivertClose(handle);
	}
	cout << "PacketDivert已结束！" << endl;
}

/// @brief 启动抓包程序
/// @param dealFunc 循环处理函数
void PacketDivert::startDivert(std::function<void(PWINDIVERT_IPHDR&, PWINDIVERT_TCPHDR&, WINDIVERT_ADDRESS&)> dealFunc)
{

	if (0 != modeFlag) {
		cerr << "error: 过滤模式不符，启动失败！" << endl;
		return;
	}

	handle = WinDivertOpen(packetFilter, filterLayer, 121/* 优先级 */, modeFlag);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const char* err_str;
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCompileFilter(
				packetFilter, WINDIVERT_LAYER_FLOW,
				NULL, 0, &err_str, NULL))
		{
			fprintf(stderr,
				"error: invalid filter \"%s\"\n",
				err_str);
			exit(-1);
		}
		fprintf(stderr,
			"error: failed to open the WinDivert device (%lu)\n",
			GetLastError());
		exit(-1);
	}



	unsigned char packet[WINDIVERT_MTU_MAX]{};

	cout << "here! modifyPacket!!" << endl;
	isLoop = true;
	WINDIVERT_ADDRESS addr;
	while (isLoop)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLength, &addr))
		{
			cerr << "failed to read packet: " << GetLastError() << endl;
			continue;
		}

		WinDivertHelperParsePacket(packet, packetLength, &ipHeader, NULL, NULL,
			NULL, NULL, &tcpHeader, NULL, NULL, NULL, NULL, NULL);
		if (ipHeader == NULL || tcpHeader == NULL)
		{
			cerr << "failed to parse packet : " << GetLastError() << endl;
			continue;
		}

		dealFunc(ipHeader, tcpHeader, addr);

		WinDivertHelperCalcChecksums(packet, packetLength, &addr, 0);
		if (!WinDivertSend(handle, packet, packetLength, NULL, &addr))
		{
			cerr << "failed to send packet :" << GetLastError() << endl;
			continue;
		}
	}
}


void PacketDivert::startDivert(std::function<void(WINDIVERT_ADDRESS)> dealFunc,	
std::map<UINT,UINT32>* mapPortPID) {

	if (mapPortPID!=nullptr){
		this->mapPortWithPID = mapPortPID;
	}


	if (0 == modeFlag) {
		cerr << "error: 过滤模式不符，启动失败！" << endl;
		return;
	}

	handle = WinDivertOpen(packetFilter, filterLayer, 125/* 优先级 */, modeFlag);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const char* err_str;
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCompileFilter(
				packetFilter, WINDIVERT_LAYER_FLOW,
				NULL, 0, &err_str, NULL))
		{
			fprintf(stderr,
				"error: invalid filter \"%s\"\n",
				err_str);
			exit(-1);
		}
		fprintf(stderr,
			"error: failed to open the WinDivert device (%lu)\n",
			GetLastError());
		exit(-1);
	}


	cout << "snaff!!!" << endl;

	thread([this]()->void {
		 this->handleFlow();
		}).detach();
		WINDIVERT_ADDRESS addr;
		while (true)
		{
			if (!WinDivertRecv(handle, NULL, 0, NULL, &addr))
			{
				fprintf(stderr, "failed to read packet (%lu)\n", GetLastError());
				continue;
			}

			switch (addr.Event)
			{
				// 流建立事件
			case WINDIVERT_EVENT_FLOW_ESTABLISHED:

				// Flow established:
//				myThreadMutex.lock();
				sniffedAddrList.push_back(addr);
//				myThreadMutex.unlock();
				break;

				// 流结束事件
			case WINDIVERT_EVENT_FLOW_DELETED:


				// Flow deleted:

                    myThreadMutex.lock();
                    for (auto iter = sniffedAddrList.begin();iter!=sniffedAddrList.end();){
                        if (memcmp(&(*iter).Flow,&addr.Flow,sizeof(addr.Flow)) == 0){
                            sniffedAddrList.erase(iter++);
                            break;
                        }else {
                            iter++;
                        }
                    }
                    myThreadMutex.unlock();


				break;
			}
		}
}


void PacketDivert::handleFlow() {

	HANDLE process, console = GetStdHandle(STD_OUTPUT_HANDLE);
	WCHAR path[MAX_PATH + 1];
	char addrStr[INET6_ADDRSTRLEN + 1];
	WCHAR* filename;
	DWORD pathLen, i;
    vector<WINDIVERT_ADDRESS> addrArray;
	UINT numOfAddr = 0;

	 while (true)
	 {
	 	// Copy a snapshot of the current flows:

         myThreadMutex.lock();
         for (auto iter = sniffedAddrList.begin();
              (iter!=sniffedAddrList.end())&&numOfAddr<MAX_FLOWS;){
             addrArray.push_back(*iter);
             numOfAddr++;
             iter++;
         }

         myThreadMutex.unlock();


//	 	putchar('\n');
//	 	SetConsoleTextAttribute(console,
//	 		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	 	for (auto iter = addrArray.begin(); iter!=addrArray.end(); iter++)
	 	{
            // 打印流信息到控制台
/*
	 		printf("%-10d ", iter->Flow.ProcessId);

	 		process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
	 			iter->Flow.ProcessId);
	 		pathLen = 0;
	 		if (process != nullptr)
	 		{
	 			pathLen = GetProcessImageFileName(process, path, sizeof(path));
	 			CloseHandle(process);
	 		}
	 		SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
	 		if (pathLen != 0)
	 		{
	 			filename = PathFindFileName(path);
	 			std::wcout << filename;
	 		}
	 		else if (iter->Flow.ProcessId == 4)
	 		{
	 			fputs("Windows              ", stdout);
	 		}
	 		else
	 		{
	 			fputs("???                  ", stdout);
	 		}
	 		SetConsoleTextAttribute(console,
	 			FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	 		switch (iter->Flow.Protocol)
	 		{
	 		case IPPROTO_TCP:
	 			SetConsoleTextAttribute(console, FOREGROUND_GREEN);
	 			printf("TCP    ");
	 			break;
	 		case IPPROTO_UDP:
	 			SetConsoleTextAttribute(console,
	 				FOREGROUND_RED | FOREGROUND_GREEN);
	 			printf("UDP    ");
	 			break;
	 		case IPPROTO_ICMP:
	 			SetConsoleTextAttribute(console, FOREGROUND_RED);
	 			printf("ICMP   ");
	 			break;
	 		case IPPROTO_ICMPV6:
	 			SetConsoleTextAttribute(console, FOREGROUND_RED);
	 			printf("ICMPV6 ");
	 			break;
	 		default:
	 			printf("%-6u ", iter->Flow.Protocol);
	 			break;
	 		}
	 		SetConsoleTextAttribute(console,
	 			FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	 		WinDivertHelperFormatIPv6Address(iter->Flow.LocalAddr, addrStr,
	 			sizeof(addrStr));
	 		printf("%s:%u %s ", addrStr, iter->Flow.LocalPort,
	 			(iter->Outbound ? "---->" : "<----"));
*/


	 		// 本地端口和PID的映射放到map里
	 		if (iter->Outbound && mapPortWithPID!=nullptr){
	 			(*mapPortWithPID)[iter->Flow.LocalPort] = iter->Flow.ProcessId;
	 		}

//            printf("remote %d\n",iter->Flow.RemotePort);
//            printf("local %d\n",iter->Flow.LocalPort);
             if (iter->Flow.RemotePort == 43010){ // 这里不用转换
//                 printf("***************\n");
                    //TODO 魔法值，有时间处理下
                 (*mapPortWithPID)[iter->Flow.LocalPort] = iter->Flow.ProcessId;
             }


//	 		WinDivertHelperFormatIPv6Address(iter->Flow.RemoteAddr, addrStr,
//	 			sizeof(addrStr));
//	 		printf("%s:%u\n", addrStr, iter->Flow.RemotePort);
//	 		fflush(stdout);
	 	}
	 	Sleep(1000);
	 }

}