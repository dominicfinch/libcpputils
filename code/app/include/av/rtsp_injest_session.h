#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <memory>

extern "C" {
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
}

namespace iar { namespace av {

class StreamBroadcaster;

class RtspIngestSession {
public:
    RtspIngestSession(const std::string& rtsp_url,
                      std::shared_ptr<StreamBroadcaster> broadcaster)
        : _rtsp_url(rtsp_url),
          _broadcaster(broadcaster) {}

    ~RtspIngestSession() {
        stop();
    }

    bool start() {
        _running = true;
        _thread = std::thread(&RtspIngestSession::run, this);
        return true;
    }

    void stop() {
        _running = false;
        if (_thread.joinable())
            _thread.join();
    }

private:
    void run() {
        AVFormatContext* fmt = nullptr;

        avformat_open_input(&fmt, _rtsp_url.c_str(), nullptr, nullptr);
        avformat_find_stream_info(fmt, nullptr);

        int video_stream = -1;
        for (unsigned i = 0; i < fmt->nb_streams; ++i) {
            if (fmt->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                video_stream = i;
                break;
            }
        }

        AVPacket pkt;
        while (_running && av_read_frame(fmt, &pkt) >= 0) {
            if (pkt.stream_index == video_stream) {
                bool keyframe = pkt.flags & AV_PKT_FLAG_KEY;
                uint64_t ts_ms =
                    pkt.pts * av_q2d(fmt->streams[video_stream]->time_base) * 1000;

                _broadcaster->broadcast_h264_frame(
                    pkt.data, pkt.size, keyframe, ts_ms);
            }
            av_packet_unref(&pkt);
        }

        avformat_close_input(&fmt);
    }

    std::string _rtsp_url;
    std::shared_ptr<StreamBroadcaster> _broadcaster;

    std::thread _thread;
    std::atomic<bool> _running{false};
};

} }