
#pragma once

#include <grpcpp/grpcpp.h>
#include "streaming.grpc.pb.h"

namespace iar { namespace app {

class StreamingService final : public rpc::StreamingService::Service {
public:
  grpc::Status CreateStream(
      grpc::ServerContext* context,
      const rpc::CreateStreamRequest* request,
      rpc::CreateStreamResponse* response) override;

  grpc::Status ListStreams(
      grpc::ServerContext* context,
      const rpc::ListStreamsRequest* request,
      rpc::ListStreamsResponse* response) override;

  grpc::Status SetRecording(
      grpc::ServerContext* context,
      const rpc::SetRecordingRequest* request,
      rpc::SetRecordingResponse* response) override;

  grpc::Status Subscribe(
      grpc::ServerContext* context,
      const rpc::SubscribeRequest* request,
      grpc::ServerWriter<rpc::StreamChunk>* writer) override;
};

} } // namespace iar::rpc
