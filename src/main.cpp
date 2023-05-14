#include "localServer/ProxyServer.h"
#include "divert/PacketDivert.h"

#include <grpcpp/security/credentials.h>
#include <grpcpp/create_channel.h>
#include "../gRpcServices/NetifePostClientImpl.h"

#include "Poco/UUID.h"
#include "Poco/UUIDGenerator.h"


using namespace std;
using Poco::UUID;
using Poco::UUIDGenerator;

//#define PROXY_PORT 34010
#define PROXY_PORT 9999
#define SSL_SERVER_PORT 443
#define SERVER_PORT 80



#define GRPC_DEBUG_MODE true
#define DEBUG_DISPATCHER_HOST "localhost"
#define DEBUG_DISPATCHER_PORT "7890"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

static map<UINT, UINT32> mapPortPID;


int main() {


    // grpc
    Netife::NetifePostClientImpl client(grpc::CreateChannel(static_cast<string>(DEBUG_DISPATCHER_HOST)  + ":" + DEBUG_DISPATCHER_PORT, grpc::InsecureChannelCredentials()));

    auto commitDataFunc = [&client](
            _In_ const std::string &originData,
            _In_ const UINT32 pid,
            _In_ const struct in_addr &serverAddr,
            _In_ const bool isOutBound,
            _Out_ std::string &newData
    ) ->int{


        newData = originData;

        auto serverIp = serverAddr.S_un.S_un_b;

        cout << "local application pid is: " << pid << endl;

        NetifeProbeRequest netifeProbeRequest;

        UUIDGenerator& generator = UUIDGenerator::defaultGenerator();
        Poco::UUID uuid(generator.create());

        netifeProbeRequest.set_uuid(uuid.toString());

        //添加 originDqta
        std::string rawText;

        rawText.assign(originData.c_str(),
                       originData.c_str() + originData.length());
        netifeProbeRequest.set_raw_text(rawText);
        netifeProbeRequest.set_pid(to_string(pid));

        //TODO 支持端口修改

        netifeProbeRequest.set_dst_ip_addr(to_string((int) serverIp.s_b1) + "." + to_string((int) serverIp.s_b2) + "." +
                                           to_string((int) serverIp.s_b3) + "." + to_string((int) serverIp.s_b4));
        netifeProbeRequest.set_protocol(NetifeMessage::NetifeProbeRequest_Protocol_TCP);

        //TODO 支持SERVER修改

        if (isOutBound){
            netifeProbeRequest.set_application_type(NetifeMessage::NetifeProbeRequest_ApplicationType_CLIENT);
        }else{
            netifeProbeRequest.set_application_type(NetifeMessage::NetifeProbeRequest_ApplicationType_SERVER);
        }


        auto response = client.ProcessProbe(netifeProbeRequest);

        if (!response.has_value()) {
            // TODO 改成错误码
            newData = originData;
            return 0;
        } else {
            newData = response.value().response_text();
            return 0;
        }

    };


//        ::system("chcp 65001");




    UINT16 serverPort = SERVER_PORT, proxyPort = PROXY_PORT, altPort = ALT_PORT;
    auto dealFunc = [&](PWINDIVERT_IPHDR &ipHeader, PWINDIVERT_TCPHDR &tcpHeader, WINDIVERT_ADDRESS &addr) {
        if (addr.Outbound) // 向外部主机发送的数据包
        {
            if (tcpHeader->DstPort == htons(serverPort)) {
                // Reflect: PORT ---> PROXY

                tcpHeader->DstPort = htons(proxyPort);
                swap(ipHeader->SrcAddr, ipHeader->DstAddr);
//                ipHeader->DstAddr = ipHeader->SrcAddr;
                addr.Outbound = FALSE;

            } else if (tcpHeader->SrcPort == htons(proxyPort)) {
                // Reflect: PROXY ---> PORT

                tcpHeader->SrcPort = htons(serverPort);
                swap(ipHeader->SrcAddr, ipHeader->DstAddr);
                addr.Outbound = FALSE;
            } else if (tcpHeader->DstPort == htons(altPort)) {
                // Redirect: ALT ---> PORT

                tcpHeader->DstPort = htons(serverPort);
            }
        } else {
            if (tcpHeader->SrcPort == htons(serverPort)) {
                // Redirect: PORT ---> ALT

                tcpHeader->SrcPort = htons(altPort);
            }
        }
    };




    // 这个地方来判断是否启用了DEBUG模式，如果启用了那么就使用DEFINE的HOST和PORT

    //TODO 这个地方需要修改！为了不侵入本REPO程序故没有修改启动逻辑


    char filter[256]{};
    snprintf(filter,sizeof(filter),
             "tcp and "
             "(tcp.DstPort != 7890 and tcp.DstPort != 7891 and tcp.DstPort != 7892 and tcp.DstPort != 7893 and "
             "tcp.SrcPort != 7890 and tcp.SrcPort != 7891 and tcp.SrcPort != 7892 and tcp.SrcPort != 7893)");


/*    snprintf(filter, sizeof(filter),
             "tcp and "
             "(tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or "
             "tcp.SrcPort == %d or tcp.SrcPort == %d or tcp.SrcPort == %d) and (ip.SrcAddr == 216.127.185.51 or ip.DstAddr == 216.127.185.51) ",
             serverPort, proxyPort, altPort, serverPort, proxyPort, altPort);*/



    ProxyServer proxyServer(proxyPort,commitDataFunc);
    PacketDivert packetDivert(filter);
    PacketDivert sniffDivert("tcp and localPort", WINDIVERT_LAYER_FLOW,
                             WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    bool one = false;
    bool two = false;
    bool three = false;
    thread([&]() -> void {
        proxyServer.startServer(256, &mapPortPID); // TODO 魔法值
        one = true;
    }).detach();

    thread([&]() -> void {
        packetDivert.startDivert(dealFunc);
        two = true;
    }).detach();

//	thread([&]()->void {
//        // new 的写法似乎存在内存泄漏问题，使用智能指针要解决生命周期问题，还是先创建对象吧
//		sniffDivert.startDivert([](WINDIVERT_ADDRESS) {},&mapPortPID);
//		three = true;
//    }).detach();

    while (one == false || two == false || three == false) {

//		for (auto elem : mapPortPID)
//		{
        //			cout << elem.first << "->"<<elem.second <<endl;
//		}
        Sleep(5000);
    }

    return 0;
}