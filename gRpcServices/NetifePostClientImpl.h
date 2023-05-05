//
// Created by Administrator on 2023/4/30.
//

#ifndef NETIFEDISPATCHER_NETIFEPOSTCLIENTIMPL_H
#define NETIFEDISPATCHER_NETIFEPOSTCLIENTIMPL_H
#include "../gRpcModel/NetifeMessage.grpc.pb.h"
#include <optional>
using namespace std;
using grpc::ChannelInterface;
using grpc::ClientContext;
using grpc::Status;
using NetifeMessage::NetifeProbeRequest;
using NetifeMessage::NetifeProbeResponse;
using NetifeMessage::NetifeService;

namespace Netife {

    class NetifePostClientImpl {
    private:
        std::unique_ptr<NetifeService::Stub> _stub;
    public:
        explicit NetifePostClientImpl(const std::shared_ptr<ChannelInterface>& channel)
            : _stub(NetifeService::NewStub(channel)) {
        }
        optional<NetifeProbeResponse> ProcessProbe(NetifeProbeRequest request);
    };

} // Netife

#endif //NETIFEDISPATCHER_NETIFEPOSTCLIENTIMPL_H
