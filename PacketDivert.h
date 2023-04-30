#ifndef __PACKETDIVERT_H__
#define __PACKETDIVERT_H__

#include <WinSock2.h>
#include <Windows.h> // 前面必须是winsock2
#include <iostream>
#include <functional>
#include <mutex>
#include <thread>

#include <psapi.h>
#include <shlwapi.h>
#define MAX_FLOWS           256
#define INET6_ADDRSTRLEN    45

#include "include/windivert.h"

typedef struct FLOW
{
	WINDIVERT_ADDRESS addr;
	struct FLOW* next;
} FLOW, * PFLOW;

class PacketDivert
{
private:
	HANDLE handle = nullptr;


	const char* packetFilter = nullptr;
	WINDIVERT_LAYER filterLayer = WINDIVERT_LAYER_NETWORK;
	UINT64 modeFlag = 0;




	UINT packetLength = 0;
	bool isLoop = false;

	PWINDIVERT_IPHDR ipHeader = nullptr;
	PWINDIVERT_TCPHDR tcpHeader = nullptr;

	std::mutex myThreadMutex;
	PFLOW flows = nullptr; /* 记录所有当前捕获的流 */

public:
	PacketDivert() = default;
	PacketDivert(const char* packetFilter, WINDIVERT_LAYER filterLayer = WINDIVERT_LAYER_NETWORK, UINT64 modeFlag = 0);
	~PacketDivert();

	void startDivert(std::function<void(PWINDIVERT_IPHDR&, PWINDIVERT_TCPHDR&, WINDIVERT_ADDRESS&)> dealFunc);

	void startDivert(std::function<void(WINDIVERT_ADDRESS)> dealFunc);
	void handleFlow();

};
#endif