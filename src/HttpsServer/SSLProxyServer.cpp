#include "SSLProxyServer.h"
#include <cassert>
#include <string>
#include <condition_variable>
#include "../utils/SafeMap.h"

using namespace sslServer;

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")
#define CERT_GEN
#define FRAMEWORK_ONE

constexpr bool isDebug = true;
// perror 后面会跟上系统错误码
static inline std::tuple<bool, int> check_if_fatal_error(_In_ int err) {
	switch (err) {
#define PER_ERROR(x) case x: {if constexpr (isDebug) perror("ssl code: "#x"\n"); return {false,x};} 

		PER_ERROR(SSL_ERROR_NONE)
			PER_ERROR(SSL_ERROR_WANT_READ)
			PER_ERROR(SSL_ERROR_WANT_WRITE)
			PER_ERROR(SSL_ERROR_WANT_CONNECT)
			PER_ERROR(SSL_ERROR_WANT_ACCEPT)
			PER_ERROR(SSL_ERROR_ZERO_RETURN)
#undef PERR_ERROR(x)

#define PER_FATAL(x) case x: {if constexpr (isDebug) perror("ssl code: "#x"\n"); return {true,x};} 
			PER_FATAL(SSL_ERROR_SSL)
			PER_FATAL(SSL_ERROR_WANT_X509_LOOKUP)
			PER_FATAL(SSL_ERROR_SYSCALL)
			PER_FATAL(SSL_ERROR_WANT_ASYNC)
			PER_FATAL(SSL_ERROR_WANT_ASYNC_JOB)
			PER_FATAL(SSL_ERROR_WANT_CLIENT_HELLO_CB)
			PER_FATAL(SSL_ERROR_WANT_RETRY_VERIFY)
	}
	return { true, err };
}




SSLProxyServer::SSLProxyServer(_In_ UINT proxyPort,
	_In_ const std::function<int(
		_In_ const std::string&,
		_In_ const UINT32&,
		_In_ const in_addr&,
		_In_ const bool&,
		_In_ const bool&,
		_Out_ std::string&)>& func
) : commitDataFunc(func) {


	// 初始化线程池

	pServerWorkPool = new ThreadPool{ 100 };
	pClientWorkPool = new ThreadPool{ 100 };
	pMonitorPool = new ThreadPool{ 100 };

	pServerWorkPool->init();
	pClientWorkPool->init();
	pMonitorPool->init();

	// init
	WORD ver = MAKEWORD(2, 2);
	WSADATA wd;
	if (WSAStartup(ver, &wd) != 0) {
		assert(0);
	}
	/*
	* 初始化 OpenSSL 库
	*/
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	const SSL_METHOD* serverMethod = SSLv23_server_method();
	serverSSLCtx = SSL_CTX_new(serverMethod);

	const SSL_METHOD* clientMethod = SSLv23_client_method();
	clientSSLCtx = SSL_CTX_new(clientMethod);
	//if (SSL_CTX_use_certificate_file(serverSSLCtx, "cache\\www.baidu.com.crt", SSL_FILETYPE_PEM) <= 0) {
	//	ERR_print_errors_fp(stderr);
	//	exit(EXIT_FAILURE);
	//}

	//if (SSL_CTX_use_PrivateKey_file(serverSSLCtx, "cache\\www.baidu.com.key", SSL_FILETYPE_PEM) <= 0) {
	//	ERR_print_errors_fp(stderr);
	//	exit(EXIT_FAILURE);
	//}

	SSL_CTX_set_client_hello_cb(serverSSLCtx,
		clientHelloSelectServerCTX,
		serverSSLCtx);


	serverSocketFD = WSASocketW(
		AF_INET,
		SOCK_STREAM,
		0,
		nullptr,
		0,
		WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == serverSocketFD) {
		closesocket(serverSocketFD);
		std::cerr << "failed to create socket: " << WSAGetLastError() << std::endl;
		exit(-2);
	}


	sockaddr_in serverAddr{};
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(proxyPort);

	::bind(serverSocketFD, (sockaddr*)&serverAddr, sizeof(sockaddr_in));

}

int SSLProxyServer::newAccept() {
	//puts("aaaaa\n");
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


	int bRetVal = AcceptEx(serverSocketFD,
		ioContext->socket,
		ioContext->addresses,
		0,
		addrLen,
		addrLen,
		nullptr,
		&ioContext->overlapped);
	if (bRetVal == FALSE) {
		int error = WSAGetLastError();
		if (error != WSA_IO_PENDING) {
			std::cerr << WSAGetLastError() << std::endl;
			closesocket(ioContext->socket);
			return -1;
		}
	}



	// 套壳ssl
	ioContext->clientSSL = SSL_new(serverSSLCtx);
	//assert(!SSL_is_init_finished(ioContext->clientSSL));

#ifdef FRAMEWORK_ONE
	SSL_set_fd(ioContext->clientSSL, ioContext->socket);


#else

	ioContext->internalBio = BIO_new(BIO_s_mem());
	ioContext->networkBio = BIO_new(BIO_s_mem());


	// 关联这对儿 bio
	SSL_set_bio(ioContext->clientSSL,
		ioContext->internalBio,
		ioContext->networkBio);


#endif // FRAMEWORK_ONE

	//BIO_new_bio_pair(&ioContext->internalBio,
	//    MaxBufferSize, 
	//    &ioContext->networkBio,
	//    MaxBufferSize);


	SSL_set_accept_state(ioContext->clientSSL);


	return 0;
}

int SSLProxyServer::newConnect(_In_ BaseIOContext* baseIoContext) {

	auto sslIOContext = reinterpret_cast<SSLIOContext*>(baseIoContext);

	WCHAR ipDotDec[20]{};
	InetNtop(AF_INET,
		(void*)&sslIOContext->addr.sin_addr,
		ipDotDec,
		sizeof(ipDotDec));

	std::wcout << "connecting: " << ipDotDec << std::endl;


	sockaddr_in remoteServerAddr{};
	remoteServerAddr.sin_family = AF_INET;
	remoteServerAddr.sin_port = htons(SSL_ALT_PORT);
	remoteServerAddr.sin_addr = sslIOContext->addr.sin_addr;



	// 这里开始 IOCP，创建新的客户端IO文件描述符，alt表示远程服务器
	sslIOContext->remoteSocket = WSASocketW(
		AF_INET,
		SOCK_STREAM,
		0,
		nullptr,
		0,
		WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == sslIOContext->remoteSocket) {
		closesocket(sslIOContext->remoteSocket);
		std::cerr << "failed to create socket: "
			<< WSAGetLastError()
			<< std::endl;
		exit(-9);
	}



	setsockopt(sslIOContext->remoteSocket,
		SOL_SOCKET,
		SO_UPDATE_CONNECT_CONTEXT,
		nullptr,
		0);



	// 和完成端口关联起来
	if (nullptr == CreateIoCompletionPort(
		(HANDLE)sslIOContext->remoteSocket,
		hIOCP,
		0,
		0)) {
		shutdown(sslIOContext->remoteSocket, SD_BOTH);
		closesocket(sslIOContext->remoteSocket);
		closesocket(sslIOContext->socket);
		assert(0);
	}


	addrinfo hints = { 0 };
	hints.ai_family = AF_INET;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	addrinfo* pAddrInfo = nullptr;
	if (auto err = getaddrinfo(nullptr,
		"",
		&hints,
		&pAddrInfo)) {

		fprintf(stderr, "getaddrinfo: %ls\n",
			gai_strerror(err));
		exit(-1);
	}
	if (SOCKET_ERROR == ::bind(sslIOContext->remoteSocket,
		pAddrInfo->ai_addr,
		static_cast<int>(pAddrInfo->ai_addrlen))) {

	}
	sslIOContext->type = EventIOType::ClientIOConnect;

	// 获取connectEx指针
	if (nullptr == pfn_ConnectEx) {
		DWORD dwRetBytes = 0;
		GUID guid = WSAID_CONNECTEX;
		WSAIoctl(sslIOContext->remoteSocket,
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			(void*)&guid,
			sizeof(guid),
			(void*)&pfn_ConnectEx,
			sizeof(pfn_ConnectEx),
			&dwRetBytes,
			nullptr,
			nullptr);
	}

	(*pfn_ConnectEx)(sslIOContext->remoteSocket,
		(sockaddr*)&remoteServerAddr,
		sizeof(sockaddr_in), nullptr, 0, nullptr,
		&sslIOContext->overlapped);




	sslIOContext->remoteSSL = SSL_new(clientSSLCtx);


	assert(!SSL_is_init_finished(sslIOContext->remoteSSL));



#ifdef FRAMEWORK_ONE

	SSL_set_fd(sslIOContext->remoteSSL, sslIOContext->remoteSocket);
#else
	sslIOContext->remoteInternalBio = BIO_new(BIO_s_mem());
	sslIOContext->remoteNetworkBio = BIO_new(BIO_s_mem());


	SSL_set_bio(sslIOContext->remoteSSL,
		sslIOContext->remoteInternalBio,
		sslIOContext->remoteNetworkBio);
#endif 


	SSL_set_connect_state(sslIOContext->remoteSSL);


	return 0;
}

void SSLProxyServer::startServer(_In_ int maxWaitList,
	_In_ std::map<UINT, UINT32>* mapPortPID) {

	if (SOCKET_ERROR == ::listen(
		serverSocketFD,
		SOMAXCONN)) {
		std::cerr << "failed to listen socket: " << WSAGetLastError() << std::endl;
		closesocket(serverSocketFD);
		exit(-5);
	}


	// 初始化 IOCP
	hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
		nullptr,
		0,
		0);
	if (INVALID_HANDLE_VALUE == hIOCP) {
		std::cerr << "FAILED TO CREATE IOCP HANDLE:" << WSAGetLastError() << std::endl;
		closesocket(serverSocketFD);
		exit(-6);
	}


	// 切记，先把serverSockerFD和iocp绑定，不然接收不到连接通知
	if (nullptr == CreateIoCompletionPort(
		(HANDLE)serverSocketFD,
		hIOCP,
		0,
		0)) {
		shutdown(serverSocketFD, SD_BOTH);
		closesocket(serverSocketFD);
		exit(-13);
	}


	// 初始化工作线程
	for (size_t i = 0; i < MaxNumberOfThreads; i++) {
		threadGroup.emplace_back([this]() { eventWorkerThread(); });
	}


	// 启动工作线程
	for (auto& t : threadGroup) {
		t.detach();
	}


	for (auto i = 0; i < 1; i++) {
		newAccept();

	}


}

int SSLProxyServer::commitData(_In_ const std::string& originData,
	_In_ const UINT32& pid,
	_In_ const in_addr& serverAddr,
	_In_ const bool& isOutBound, std::string& newData) {


	return this->commitDataFunc(originData,
		pid,
		serverAddr,
		isOutBound,
		true,
		newData);
}

void SSLProxyServer::eventWorkerThread() {
	//puts("worker");
	SSLIOContext* ioContext = nullptr;
	DWORD lpNumberOfBytesTransferred = 0;
	void* lpCompletionKey = nullptr;

	while (true) {
		BOOL bRt = GetQueuedCompletionStatus(
			hIOCP,
			&lpNumberOfBytesTransferred,
			(PULONG_PTR)&lpCompletionKey,
			(LPOVERLAPPED*)&ioContext,
			INFINITE);

		// IO 未完成

		if (!bRt) continue;

		// 收到 PostQueuedCompletionStatus 发出的退出指令
		if (lpNumberOfBytesTransferred == -1) break;

		// 没有可操作数据，但是是连接请求，需要接受！
		if (lpNumberOfBytesTransferred == 0) {
			switch (ioContext->type) {
			case EventIOType::ServerIOAccept:
			case EventIOType::ClientIOConnect:
				//case EventIOType::ServerIOHandshake:
				//case EventIOType::ClientIOHandshake:
				//assert(0);
				break;



			default:
				continue;
			}
		}


		// 处理对应的事件

		switch (ioContext->type) {
		case EventIOType::ServerIOAccept: {

			puts("accept!\n");
			newAccept();

			auto newAddr =
				*reinterpret_cast<sockaddr_in*>
				(&ioContext->addresses[1]);

			WCHAR ipDotDec[20]{};
			InetNtop(AF_INET,
				(void*)&newAddr.sin_addr,
				ipDotDec,
				sizeof(ipDotDec));
			std::wcout << L"new accept event: to " << ipDotDec << std::endl;

			ioContext->addr = newAddr;
			newConnect(ioContext);
			break;
		}
		case EventIOType::ClientIOConnect: {
			puts("connect finished...\n");






			auto r = SSL_do_handshake(ioContext->clientSSL);
			auto err = SSL_get_error(ioContext->clientSSL, r);
			if (r != 1) {

				shutdown(ioContext->socket, SD_BOTH);
				SSL_shutdown(ioContext->clientSSL);
				SSL_free(ioContext->clientSSL);

				shutdown(ioContext->remoteSocket, SD_BOTH);
				SSL_shutdown(ioContext->remoteSSL);
				SSL_free(ioContext->remoteSSL);

				delete ioContext;
				break;
			}

			auto r_ = SSL_do_handshake(ioContext->remoteSSL);
			auto err_ = SSL_get_error(ioContext->remoteSSL, r_);
			if (r_ != 1) {

				SSL_shutdown(ioContext->clientSSL);
				SSL_free(ioContext->clientSSL);
				shutdown(ioContext->socket, SD_BOTH);
				closesocket(ioContext->socket);


				SSL_shutdown(ioContext->remoteSSL);
				SSL_free(ioContext->remoteSSL);
				shutdown(ioContext->remoteSocket, SD_BOTH);
				closesocket(ioContext->remoteSocket);

				delete ioContext;

				break;
			}


			pServerWorkPool->submit([ioContext, this] {
				while (ioContext->isServerRun) {
					char buf[MaxBufferSize]{};
					std::string res;
					while (true) {
						auto rt = SSL_read(ioContext->clientSSL, buf, sizeof(buf));
						if (rt <= 0) {
							int err = SSL_get_error(ioContext->remoteSSL, rt);
							auto [isFatal, errCode] = check_if_fatal_error(err);
							ioContext->isServerRun = false;
							return;
						}
						res.append(buf, rt);
						if (rt < MaxBufferSize)break;
					}

					ioContext->sendToServerRaw.clear();
					res = myToHex(res);
					//assert(res == myToBytes(myToHex(res)));
					commitData(res, 0, ioContext->addr.sin_addr, true, ioContext->sendToServerRaw);
					std::cerr << ioContext->sendToServerRaw << std::endl;
					//std::cerr << res << std::endl;

					ioContext->sendToServerRaw = myToBytes(ioContext->sendToServerRaw);
					auto t1 = SSL_write(ioContext->remoteSSL,
						ioContext->sendToServerRaw.c_str(),
						ioContext->sendToServerRaw.length());

					res.clear();

				}
				});

			pClientWorkPool->submit([ioContext, this] {
				while (ioContext->isClientRun) {
					char buf[MaxBufferSize]{};
					std::string res;
					while (true) {
						auto rt = SSL_read(ioContext->remoteSSL, buf, sizeof(buf));
						if (rt <= 0) {
							int err = SSL_get_error(ioContext->remoteSSL, rt);
							auto [isFatal, errCode] = check_if_fatal_error(err);

							ioContext->isClientRun = false;
							return;
						}
						res.append(buf, rt);
						if (rt < MaxBufferSize)break;

					}

					ioContext->sendToClientRaw.clear();

					res = myToHex(res);
					commitData(res, 0, ioContext->addr.sin_addr, false, ioContext->sendToClientRaw);
					//std::cout << ioContext->sendToClientRaw << std::endl;

					ioContext->sendToClientRaw = myToBytes(ioContext->sendToClientRaw);


					auto t1 = SSL_write(ioContext->clientSSL,
						ioContext->sendToClientRaw.c_str(),
						ioContext->sendToClientRaw.length());
					res.clear();
				}

				});

			pMonitorPool->submit([ioContext, this] {
				while (ioContext->isClientRun || ioContext->isServerRun) {
					Sleep(2000);
				}

				SSL_shutdown(ioContext->clientSSL);
				SSL_free(ioContext->clientSSL);
				shutdown(ioContext->socket, SD_BOTH);
				closesocket(ioContext->socket);


				SSL_shutdown(ioContext->remoteSSL);
				SSL_free(ioContext->remoteSSL);
				shutdown(ioContext->remoteSocket, SD_BOTH);
				closesocket(ioContext->remoteSocket);
				ioContext->sendToClientRaw.clear();
				ioContext->sendToServerRaw.clear();
				delete ioContext;

				MYPRINT("delete ioContext...");
				});



				break;
		}



		default:
			break;
		}


	}


}

int SSLProxyServer::clientHelloSelectServerCTX(_In_ SSL* ssl,
	_In_ int* ignore,
	_In_ void* arg) {
	const char* servername;
	const unsigned char* p;
	size_t len, remaining;
	if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &p,
		&remaining) ||
		remaining <= 2) {
		SSL_CTX_use_certificate_file(static_cast<SSL_CTX*>(arg), "cache\\www.baidu.com.crt", SSL_FILETYPE_PEM);
		auto m = SSL_CTX_use_PrivateKey_file(static_cast<SSL_CTX*>(arg), "cache\\www.baidu.com.key", SSL_FILETYPE_PEM);
		return 1;
	}
	/* Extract the length of the supplied list of names. */
	len = (*(p++) << 8);
	len += *(p++);
	if (len + 2 != remaining)
		return 0;
	remaining = len;
	/*
	 * The list in practice only has a single element, so we only consider
	 * the first one.
	 */
	if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
		return 0;
	remaining--;
	/* Now we can finally pull out the byte array with the actual hostname. */
	if (remaining <= 2)
		return 0;
	len = (*(p++) << 8);
	len += *(p++);
	if (len + 2 > remaining)
		return 0;
	remaining = len;
	servername = (const char*)p;

	std::string serverHostname;
	if (servername != nullptr) {
		serverHostname.append(servername, remaining);
	}
	if (serverHostname.length() > 0) {
		auto* new_ctx = static_cast<SSL_CTX*>(arg);
		SSL_set_SSL_CTX(ssl, new_ctx);
		SSL_set_options(ssl, SSL_CTX_get_options(new_ctx));
		// 根据得到的域名来重新生成证书并指定路径
		// 维护一个线程安全的 map


		std::cout << "serverHostname = " << serverHostname << std::endl;

		std::string keyFilePath = "cache\\" + serverHostname + ".key";
		std::string certFilePath = "cache\\" + serverHostname + ".crt";
		certMtx.lock();
		if (!checkIfCertFileExists(keyFilePath) ||
			!checkIfCertFileExists(certFilePath)
			) {

			//std::cout << keyFilePath << std::endl;
#ifdef CERT_GEN
			// 生成证书
			std::string cmdOfCert;
			cmdOfCert.append("kill-cert\\mkcert.exe -key-file ")
				.append(keyFilePath + " ")
				.append("-cert-file ")
				.append(certFilePath + " ")
				.append(serverHostname);
			std::cout << cmdOfCert << std::endl;
			::system(cmdOfCert.c_str());
#endif // CERT_GEN


		}


		certMtx.unlock();
		SSL_use_certificate_file(ssl, certFilePath.c_str(), SSL_FILETYPE_PEM);
		auto m = SSL_use_PrivateKey_file(ssl, keyFilePath.c_str(), SSL_FILETYPE_PEM);
		assert(m == 1);
		return 1;

	}


	return 0;
}

bool SSLProxyServer::checkIfCertFileExists(const std::string& filePath) {
	{
		//std::lock_guard<std::mutex> lg(mtx);
		std::filesystem::path dir("cache"); // 该文件创建在 构建后的 DEBUG 目录中
		if (!std::filesystem::exists("cache")) {
			std::filesystem::create_directory("cache");
			return false;
		}

		std::filesystem::directory_iterator files("cache");
		for (auto& file : files) {
			if (file.path() == filePath)return true;
		}
		return false;

		// 相当于上面的判断
//        return std::any_of(begin(files), end(files),
//                           [&filePath](auto &file) {
//                               return file.path() == filePath;
//                           });

	}
}


