#pragma once

#include <memory>
#include <unordered_map>

#include "packet_broadcaster.h"
#include "rtsp_injest_session.h"

namespace iar { namespace av { 

    struct StreamContext {
        std::unique_ptr<RtspIngestSession> ingest;
        std::shared_ptr<PacketBroadcaster> broadcaster;
        //std::shared_ptr<Recorder> recorder;
    };

    class StreamManager {
    public:
        bool start_stream(const std::string& stream_id, const std::string& rtsp_url);

        void stop_stream(const std::string& stream_id);
        void start_recording(const std::string& stream_id);
        void stop_recording(const std::string& stream_id);

    private:
        std::unordered_map<std::string, StreamContext> streams_;
    };

} }