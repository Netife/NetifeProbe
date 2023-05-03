#ifndef __PACKETDIVERT_H__
#define __PACKETDIVERT_H__

#include <WinSock2.h>
#include <windows.h> // 前面必须是winsock2
#include <iostream>
#include <functional>
#include <mutex>
#include <thread>
#include <map>
#include <list>

#include <psapi.h>
#include <shlwapi.h>
#define MAX_FLOWS           256
#define INET6_ADDRSTRLEN    45

#include "include/windivert.h"


class PacketDivert
{

private:
	HANDLE handle = nullptr;

	std::map<UINT,UINT32>* mapPortWithPID = nullptr; /* 端口和pid的映射 */
	std::list<WINDIVERT_ADDRESS> sniffedAddrList; /* 嗅探到的包地址信息 */


	const char* packetFilter = nullptr;
	WINDIVERT_LAYER filterLayer = WINDIVERT_LAYER_NETWORK;
	UINT64 modeFlag = 0;




	UINT packetLength = 0;
	bool isLoop = false;

	PWINDIVERT_IPHDR ipHeader = nullptr;
	PWINDIVERT_TCPHDR tcpHeader = nullptr;

	std::mutex myThreadMutex;

public:
	PacketDivert() = default;
    explicit PacketDivert(const char* packetFilter, WINDIVERT_LAYER filterLayer = WINDIVERT_LAYER_NETWORK, UINT64 modeFlag = 0);
	~PacketDivert();

	void startDivert(const std::function<void(PWINDIVERT_IPHDR&, PWINDIVERT_TCPHDR&, WINDIVERT_ADDRESS&)>& dealFunc);

	void startDivert(const std::function<void(WINDIVERT_ADDRESS &)> &dealFunc, std::map<UINT,UINT32>* mapPortPID = nullptr);
	void handleFlow();

};
#endif