#pragma once

#include <mutex>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>

#include "generated/streaming.pb.h"
#include "generated/streaming.grpc.pb.h"

namespace iar { namespace av {

    class StreamBroadcaster {
    public:
        explicit StreamBroadcaster(const std::string& stream_id) : _stream_id(stream_id) {}

        // gRPC subscription
        void add_grpc_subscriber(std::shared_ptr<grpc::ServerWriter<iar::rpc::StreamChunk>> writer)
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _grpc_subscribers.push_back(writer);
        }

        void enable_recording(bool enable) {
            _recording_enabled.store(enable);
        }

        bool is_recording() const {
            return _recording_enabled.load();
        }

        // Called by RtspIngestSession
        void broadcast_h264_frame(const uint8_t* data, size_t size, bool keyframe, uint64_t ts_ms)
        {
            iar::rpc::StreamChunk chunk;
            chunk.set_data(data, size);
            chunk.set_timestamp_ms(ts_ms);
            chunk.set_keyframe(keyframe);

            std::lock_guard<std::mutex> lock(_mutex);

            for (auto& writer : _grpc_subscribers) {
                writer->Write(chunk);
            }

            if (_recording_enabled) {
                // TODO: push to cloud recorder (GCS)
            }
        }

    private:
        std::string _stream_id;
        std::mutex _mutex;
        std::vector<std::shared_ptr<grpc::ServerWriter<iar::rpc::StreamChunk>>> _grpc_subscribers;
        std::atomic<bool> _recording_enabled{false};
    };

} }