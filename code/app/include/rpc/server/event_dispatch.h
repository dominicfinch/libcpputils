
#pragma once

#include "interfaces/rpc.h"
#include <grpcpp/grpcpp.h>
#include "event_dispatch.grpc.pb.h"

namespace iar { namespace app {

    class EventDispatchService final : public rpc::EventDispatchService::Service, public rpc::irpc_service
    {
        public:
        
        EventDispatchService(app::security_service_context * ssc): rpc::irpc_service(ssc) {}

        grpc::Status PublishEvent(grpc::ServerContext* context, const rpc::EventEnvelope* request, rpc::PublishEventResponse* response) override;

        
    };

} } // namespace iar::rpc
