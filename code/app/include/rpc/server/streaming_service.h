
#pragma once

#include <memory>
#include <grpcpp/grpcpp.h>
#include "streaming.grpc.pb.h"

namespace iar {

    namespace av {
        class StreamManager;
    }
    
    namespace app {

    class StreamingService final : public rpc::StreamingService::Service
    {
    public:
        StreamingService(std::shared_ptr<iar::av::StreamManager>& sm): _streamManager(sm) {}

        grpc::Status CreateStream(grpc::ServerContext* context, const rpc::CreateStreamRequest* request, rpc::CreateStreamResponse* response) override;

        grpc::Status ListStreams(grpc::ServerContext* context, const rpc::ListStreamsRequest* request, rpc::ListStreamsResponse* response) override;

        grpc::Status SetRecording(grpc::ServerContext* context, const rpc::SetRecordingRequest* request, rpc::SetRecordingResponse* response) override;

        grpc::Status Subscribe(grpc::ServerContext* context, const rpc::SubscribeRequest* request, grpc::ServerWriter<rpc::StreamChunk>* writer) override;

    private:
        std::shared_ptr<iar::av::StreamManager> _streamManager = nullptr;
    };

} } // namespace iar::rpc
