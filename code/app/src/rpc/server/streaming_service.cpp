
#include "rpc/server/streaming_service.h"

#include <iostream>
#include <thread>
#include <chrono>

#include "uuid.h"

namespace iar { namespace app {

grpc::Status StreamingService::CreateStream(grpc::ServerContext*, const rpc::CreateStreamRequest* request, rpc::CreateStreamResponse* response)
{
    std::string id = iar::utils::generate_uuid();

    _stream_manager.create_stream(id, request->source().url());

    response->mutable_stream_id()->set_id(id);
    return grpc::Status::OK;
}

grpc::Status StreamingService::ListStreams(
    grpc::ServerContext*,
    const rpc::ListStreamsRequest*,
    rpc::ListStreamsResponse* response) {

  // TODO:
  // - Return active stream registry

  return grpc::Status::OK;
}

grpc::Status StreamingService::SetRecording(grpc::ServerContext*, const rpc::SetRecordingRequest* request, rpc::SetRecordingResponse* response)
{
    _stream_manager.set_recording(
        req->stream_id().value(), req->enable());

    resp->set_recording(req->enable());
    return grpc::Status::OK;
}

grpc::Status StreamingService::Subscribe(grpc::ServerContext* context, const rpc::SubscribeRequest* request, grpc::ServerWriter<rpc::StreamChunk>* writer)
{

    std::cout << "[StreamingService] Client subscribed to stream " << request->stream_id().id() << std::endl;
    auto broadcaster = _stream_manager.get_broadcaster(request->stream_id().value());

    if (!broadcaster) {
        return grpc::Status(grpc::NOT_FOUND, "Stream not found");
    }

    broadcaster->add_grpc_subscriber(
        std::shared_ptr<grpc::ServerWriter<iar::rpc::StreamChunk>>(writer,
                                                                  [](auto*){}));

    // Block until client disconnects
    while (!context->IsCancelled()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return grpc::Status::OK;
}

} } // namespace iar::rpc
