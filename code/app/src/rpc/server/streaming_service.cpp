
#include "rpc/server/streaming_service.h"

#include <iostream>
#include <thread>
#include <chrono>

namespace iar { namespace app {

grpc::Status StreamingService::CreateStream(
    grpc::ServerContext*,
    const rpc::CreateStreamRequest* request,
    rpc::CreateStreamResponse* response) {

  // TODO:
  // - Validate RTSP URL
  // - Start FFmpeg ingest
  // - Register stream internally

  response->mutable_stream_id()->set_id("stream-uuid-placeholder");

  std::cout << "[StreamingService] Created stream: "
            << request->source().url() << std::endl;

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

grpc::Status StreamingService::SetRecording(
    grpc::ServerContext*,
    const rpc::SetRecordingRequest* request,
    rpc::SetRecordingResponse* response) {

  // TODO:
  // - Toggle recording pipeline
  // - Notify EventDispatchService

  response->set_recording(request->enable());

  std::cout << "[StreamingService] Recording "
            << (request->enable() ? "ENABLED" : "DISABLED")
            << " for stream " << request->stream_id().id() << std::endl;

  return grpc::Status::OK;
}

grpc::Status StreamingService::Subscribe(
    grpc::ServerContext* context,
    const rpc::SubscribeRequest* request,
    grpc::ServerWriter<rpc::StreamChunk>* writer) {

  std::cout << "[StreamingService] Client subscribed to stream "
            << request->stream_id().id() << std::endl;

  // TODO:
  // - Pull frames from RTSP
  // - Forward encoded chunks

  while (!context->IsCancelled()) {
    rpc::StreamChunk chunk;
    chunk.set_timestamp_ms(
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count()));
    chunk.set_keyframe(true);
    chunk.set_data("dummy_frame_data");

    writer->Write(chunk);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  return grpc::Status::OK;
}

} } // namespace iar::rpc
