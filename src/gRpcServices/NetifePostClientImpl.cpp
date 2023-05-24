//
// Created by Administrator on 2023/4/30.
//

#include "NetifePostClientImpl.h"
#include <grpcpp/grpcpp.h>

namespace Netife {
    optional<NetifeProbeResponse> NetifePostClientImpl::ProcessProbe(NetifeProbeRequest request) {
        NetifeProbeResponse response;
        ClientContext context;
        Status status = _stub->ProcessProbe(&context, request, &response);
        if (status.ok()) {
            return response;
        } else {
            return nullopt;
        }
    }
} // Netife