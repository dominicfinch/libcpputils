#pragma once

#include "interfaces/av.h"
#include <unordered_map>
#include <mutex>
#include <memory>

#include "stream_broadcaster.h"
#include "rtsp_injest_session.h"

namespace iar { namespace av {

    class StreamManager: public istream_manager
    {
    public:
        bool create_stream(const std::string& stream_id, const std::string& rtsp_url)
        {
            std::lock_guard<std::mutex> lock(_mutex);

            auto broadcaster = std::make_shared<StreamBroadcaster>(stream_id);
            auto ingest = std::make_shared<RtspIngestSession>(stream_id, rtsp_url);

            ingest->Start();
            _streams.emplace(stream_id, StreamContext{ ingest, broadcaster });
            return true;
        }

        void set_recording(const std::string& stream_id, bool enable)
        {
            auto s = get(stream_id);
            if (s) s->broadcaster->enable_recording(enable);
        }


        std::shared_ptr<StreamBroadcaster>
        get_broadcaster(const std::string& stream_id)
        {
            auto s = get(stream_id);
            return s ? s->broadcaster : nullptr;
        }

    private:
        struct StreamContext
        {
            std::shared_ptr<RtspIngestSession> ingest;
            std::shared_ptr<StreamBroadcaster> broadcaster;
        };

        StreamContext* get(const std::string& id)
        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto it = _streams.find(id);
            return it == _streams.end() ? nullptr : &it->second;
        }

        std::mutex _mutex;
        std::unordered_map<std::string, StreamContext> _streams;
    };

} }