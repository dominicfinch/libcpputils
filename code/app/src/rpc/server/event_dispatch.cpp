
#include "rpc/server/event_dispatch.h"

grpc::Status iar::app::EventDispatchService::PublishEvent(grpc::ServerContext* context, const rpc::EventEnvelope* request, rpc::PublishEventResponse* response)
{


    return grpc::Status::OK;
}