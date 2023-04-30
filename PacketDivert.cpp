#include "PacketDivert.h"

using namespace std;
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")



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

	handle = WinDivertOpen(packetFilter, filterLayer, 123/* 优先级 */, modeFlag);
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
			"error: failed to open the WinDivert device (%d)\n",
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


void PacketDivert::startDivert(std::function<void(WINDIVERT_ADDRESS)> dealFunc) {


	if (0 == modeFlag) {
		cerr << "error: 过滤模式不符，启动失败！" << endl;
		return;
	}

	handle = WinDivertOpen(packetFilter, filterLayer, 123/* 优先级 */, modeFlag);
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
			"error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(-1);
	}


	cout << "snaff!!!" << endl;

	thread([this]()->void {
		this->handleFlow();
		}).detach();
		WINDIVERT_ADDRESS addr;
		PFLOW flow, prev;
		while (true)
		{
			if (!WinDivertRecv(handle, NULL, 0, NULL, &addr))
			{
				fprintf(stderr, "failed to read packet (%d)\n", GetLastError());
				continue;
			}

			switch (addr.Event)
			{
				// 流建立事件
			case WINDIVERT_EVENT_FLOW_ESTABLISHED:

				// Flow established:
				flow = new FLOW();
				if (flow == nullptr)
				{
					fprintf(stderr, "error: failed to allocate memory\n");
					exit(EXIT_FAILURE);
				}
				memcpy(&flow->addr, &addr, sizeof(flow->addr));
				myThreadMutex.lock();
				flow->next = flows;
				flows = flow;
				myThreadMutex.unlock();
				break;

				// 流结束事件
			case WINDIVERT_EVENT_FLOW_DELETED:

				// Flow deleted:
				prev = NULL;
				myThreadMutex.lock();
				flow = flows;
				while (flow != nullptr)
				{
					if (memcmp(&addr.Flow, &flow->addr.Flow,
						sizeof(addr.Flow)) == 0)
					{
						if (prev != nullptr)
						{
							prev->next = flow->next;
						}
						else
						{
							flows = flow->next;
						}
						break;
					}
					prev = flow;
					flow = flow->next;
				}
				myThreadMutex.unlock();
				delete(flow);
			}
		}
}


void PacketDivert::handleFlow() {

	const COORD top_left = { 0, 0 };
	HANDLE process, console = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO screen;
	WCHAR path[MAX_PATH + 1];
	char addr_str[INET6_ADDRSTRLEN + 1];
	WCHAR* filename;
	const WCHAR header[] = L"PID        PROGRAM              PROT   FLOW";
	DWORD rows, columns, written, fill_len, path_len, i;
	PFLOW flow;
	WINDIVERT_ADDRESS addrs[MAX_FLOWS], * addr;
	UINT num_addrs;

	while (true)
	{
		GetConsoleScreenBufferInfo(console, &screen);
		SetConsoleCursorPosition(console, top_left);

		rows = screen.srWindow.Bottom - screen.srWindow.Top + 1;
		columns = screen.srWindow.Right - screen.srWindow.Left + 1;

		// Copy a snapshot of the current flows:
		myThreadMutex.lock();
		flow = flows;
		num_addrs = 0;
		for (i = 0; flow != NULL && i < rows && i < MAX_FLOWS; i++)
		{
			memcpy(&addrs[i], &flow->addr, sizeof(addrs[i]));
			num_addrs++;
			flow = flow->next;
		}
		myThreadMutex.unlock();

		std::wcout << header << std::endl;
		fill_len = columns - (sizeof(header) - 1);
		if (fill_len > 0)
		{
			COORD pos = { sizeof(header) - 1, 0 };
		}
		putchar('\n');
		SetConsoleTextAttribute(console,
			FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		for (i = 0; i < num_addrs && i < rows - 1; i++)
		{
			COORD pos = { 0, static_cast<SHORT>(i + 1) };
			addr = &addrs[i];
			FillConsoleOutputCharacterA(console, ' ', columns, pos, &written);
			FillConsoleOutputAttribute(console,
				FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
				columns, pos, &written);
			SetConsoleCursorPosition(console, pos);
			if (i == rows - 2 && (i + 1) < num_addrs)
			{
				fputs("...", stdout);
				fflush(stdout);
				continue;
			}

			printf("%-10d ", addr->Flow.ProcessId);

			process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
				addr->Flow.ProcessId);
			path_len = 0;
			if (process != NULL)
			{
				path_len = GetProcessImageFileName(process, path, sizeof(path));
				CloseHandle(process);
			}
			SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
			if (path_len != 0)
			{
				filename = PathFindFileName(path);
				std::wcout << filename;
			}
			else if (addr->Flow.ProcessId == 4)
			{
				fputs("Windows              ", stdout);
			}
			else
			{
				fputs("???                  ", stdout);
			}
			SetConsoleTextAttribute(console,
				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			switch (addr->Flow.Protocol)
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
				printf("%-6u ", addr->Flow.Protocol);
				break;
			}
			SetConsoleTextAttribute(console,
				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			WinDivertHelperFormatIPv6Address(addr->Flow.LocalAddr, addr_str,
				sizeof(addr_str));
			printf("%s:%u %s ", addr_str, addr->Flow.LocalPort,
				(addr->Outbound ? "---->" : "<----"));
			WinDivertHelperFormatIPv6Address(addr->Flow.RemoteAddr, addr_str,
				sizeof(addr_str));
			printf("%s:%u", addr_str, addr->Flow.RemotePort);
			fflush(stdout);
		}
		for (; i < rows - 1; i++)
		{
			COORD pos = { 0, static_cast<SHORT>(i + 1) };
			FillConsoleOutputCharacterA(console, ' ', columns, pos, &written);
			FillConsoleOutputAttribute(console,
				FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
				columns, pos, &written);
		}

		Sleep(1000);
	}

}
