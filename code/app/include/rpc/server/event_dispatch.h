
#pragma once

#include <grpcpp/grpcpp.h>
#include "event_dispatch.grpc.pb.h"

namespace iar { namespace app {

class EventDispatchService final : public rpc::EventDispatchService::Service
{
public:
  grpc::Status PublishEvent(grpc::ServerContext* context, const rpc::EventEnvelope* request, rpc::PublishEventResponse* response) override;

  
};

} } // namespace iar::rpc
