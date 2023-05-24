#include "PacketDivert.h"
#include <vector>

using namespace std;
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")

#define MAX_FLOWS 256
PacketDivert::PacketDivert(const char *packetFilter,
                           WINDIVERT_LAYER filterLayer, UINT64 modeFlag
                           ) : packetFilter(packetFilter), filterLayer(filterLayer), modeFlag(modeFlag)
{
}

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
void PacketDivert::startDivert(
        const std::function<void(
                PWINDIVERT_IPHDR &,
                PWINDIVERT_TCPHDR &,
                WINDIVERT_ADDRESS &)> &dealFunc,
                INT16 priority)
{

	if (0 != modeFlag)
	{
		cerr << "error: 过滤模式不符，启动失败！" << endl;
		return;
	}

	handle = WinDivertOpen(packetFilter, filterLayer, priority /* 优先级 */, modeFlag);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const char *err_str;
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCompileFilter(
				packetFilter, WINDIVERT_LAYER_FLOW,
				nullptr, 0, &err_str, nullptr))
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

		WinDivertHelperParsePacket(packet, packetLength,
                                   &ipHeader, nullptr, nullptr,
								   nullptr, nullptr, &tcpHeader,
                                   nullptr, nullptr, nullptr,
                                   nullptr, nullptr);
		if (ipHeader == nullptr || tcpHeader == nullptr)
		{
//			cerr << "failed to parse packet : " << GetLastError() << endl;
			continue;
		}

		dealFunc(ipHeader, tcpHeader, addr);

		WinDivertHelperCalcChecksums(packet, packetLength, &addr, 0);
		if (!WinDivertSend(handle, packet, packetLength, nullptr, &addr))
		{
			cerr << "failed to send packet :" << GetLastError() << endl;
			continue;
		}
	}
}

void PacketDivert::startDivert(const std::function<void(WINDIVERT_ADDRESS &)> &dealFunc,
							   std::map<UINT, UINT32> *mapPortPID)
{

	if (mapPortPID != nullptr)
	{
		this->mapPortWithPID = mapPortPID;
	}

	if (0 == modeFlag)
	{
		cerr << "error: 过滤模式不符，启动失败！" << endl;
		return;
	}

	handle = WinDivertOpen(packetFilter, filterLayer, 125 /* 优先级 */, modeFlag);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const char *err_str;
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCompileFilter(
				packetFilter, WINDIVERT_LAYER_FLOW,
				nullptr, 0, &err_str, nullptr))
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

	thread([this]() -> void
		   { this->handleFlow(); })
		.detach();
	WINDIVERT_ADDRESS addr;
	while (true)
	{
		if (!WinDivertRecv(handle, nullptr, 0, nullptr, &addr))
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
			for (auto iter = sniffedAddrList.begin(); iter != sniffedAddrList.end();)
			{
				if (memmove(&(*iter).Flow, &addr.Flow, sizeof(addr.Flow)) == 0)
				{
					sniffedAddrList.erase(iter++);
					break;
				}
				else
				{
					iter++;
				}
			}
			myThreadMutex.unlock();

			break;
            default:
                cerr<<"illegal addr.Event: "<<addr.Event<<endl;
                exit(-1);
                break;
		}
	}
}

void PacketDivert::handleFlow()
{

	vector<WINDIVERT_ADDRESS> addrArray;
	UINT numOfAddr = 0;

	while (true)
	{
		// Copy a snapshot of the current flows:

		// 解决“神秘包问题”（其实不是）
		numOfAddr = 0;

		myThreadMutex.lock();
		for (auto iter = sniffedAddrList.begin();
			 (iter != sniffedAddrList.end()) && numOfAddr < MAX_FLOWS;)
		{
			addrArray.push_back(*iter);
			numOfAddr++;
			iter++;
		}

		myThreadMutex.unlock();

		for (auto iter = addrArray.begin(); iter != addrArray.end(); iter++)
		{
			// 本地端口和PID的映射放到map里
			if (iter->Outbound && mapPortWithPID != nullptr)
			{
				(*mapPortWithPID)[iter->Flow.LocalPort] = iter->Flow.ProcessId;
			}

			if (iter->Flow.RemotePort == 43010)
			{	// 这里不用转换
				//                 printf("***************\n");
				// TODO 魔法值，有时间处理下
				(*mapPortWithPID)[iter->Flow.LocalPort] = iter->Flow.ProcessId;
			}

		}

		// 清空快照，不累计

		addrArray.clear();
		Sleep(1000);
	}
}
