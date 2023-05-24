#include "SSLProxyServer.h"
#include <cassert>


using namespace sslServer;

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")


SSLProxyServer::SSLProxyServer(_In_ UINT proxyPort,
                               _In_ const std::function<int(
        _In_ const std::string &,
        _In_ const UINT32 &,
        _In_ const in_addr &,
        _In_ const bool &,
        _In_ const bool &,
        _Out_ std::string &)> &func
) : commitDataFunc(func) {


}

int SSLProxyServer::newAccept() {

    // 这里创建最初的 io上下文
    auto ioContext = new SSLIOContext;
    ioContext->type = EventIOType::ServerIOAccept;
    //提前准备好 clientSocketFD
    ioContext->socket = WSASocket(AF_INET,
                                  SOCK_STREAM,
                                  IPPROTO_TCP,
                                  nullptr,
                                  0,
                                  WSA_FLAG_OVERLAPPED);






    // 切记，也要和iocp绑定，不然后续send recv事件没办法通知
    if (nullptr == CreateIoCompletionPort(
            (HANDLE)ioContext->socket,
            hIOCP,
            0,
            0)) {
        shutdown(ioContext->socket, SD_BOTH);
        closesocket(ioContext->socket);
        exit(-15);
    }

    //存放网络地址的长度
    int addrLen = sizeof(sockaddr_storage);
    std::cout << " sizeof(sockaddr_in) =" << sizeof(sockaddr_in) << std::endl;
    std::cout << " sizeof(sockaddr_storage) =" << sizeof(sockaddr_storage) << std::endl;


    int bRetVal = AcceptEx(serverSocketFD, ioContext->socket, ioContext->addresses,
                           0, addrLen, addrLen,
                           nullptr, &ioContext->overlapped);
    if (bRetVal == FALSE)
    {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING)
        {
            std::cerr << WSAGetLastError() << std::endl;
            closesocket(ioContext->socket);
            return 0;
        }
    }



    // 套壳ssl
    ioContext->clientSSL = SSL_new(serverSSLCtx);
    assert(!SSL_is_init_finished(ioContext->clientSSL));
    ioContext->rbio = BIO_new(BIO_s_mem());
    ioContext->wbio = BIO_new(BIO_s_mem()); // 理论上无限大，且动态增长
    SSL_set_bio(ioContext->clientSSL,
                ioContext->rbio,
                ioContext->wbio); // 这个表示，把ssl读写的缓冲区和我们做的bio缓冲区相关联
    SSL_set_accept_state(ioContext->clientSSL);




    return 1;
}

int SSLProxyServer::newConnect(_In_ IOContext *ioContext) {
    return 0;
}

void SSLProxyServer::startServer(_In_ int maxWaitList,
                                 _In_ std::map<UINT, UINT32> *mapPortPID) {

}

int SSLProxyServer::commitData(_In_ const std::string &originData,
                               _In_ const UINT32 &pid,
                               _In_ const in_addr &serverAddr,
                               _In_ const bool &isOutBound, std::string &newData) {


    return this->commitDataFunc(originData,
                                pid,
                                serverAddr,
                                isOutBound,
                                true,
                                newData);
}

void SSLProxyServer::eventWorkerThread() {

}


