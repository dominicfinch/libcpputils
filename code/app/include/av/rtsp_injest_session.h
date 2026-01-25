#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

extern "C" {
#include <libavformat/avformat.h>
}

namespace iar { namespace av {

    class RtspIngestSession {
        public:
            using PacketCallback = std::function<void(const AVPacket&)>;

            RtspIngestSession(std::string rtsp_url);
            ~RtspIngestSession();

            bool start();
            void stop();

            void set_packet_callback(PacketCallback cb);

            private:
            void ingest_loop();

            std::string rtsp_url_;
            std::atomic<bool> running_{false};
            std::thread worker_;

            AVFormatContext* fmt_ctx_ = nullptr;
            PacketCallback packet_cb_;
    };

} }