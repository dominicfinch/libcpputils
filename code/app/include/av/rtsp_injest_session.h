#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <memory>

extern "C" {
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
}

#include "streaming.grpc.pb.h"
#include "av/recording_session.h"

namespace iar { namespace av {

    class StreamBroadcaster;

    struct EncodedPacket {
        std::vector<uint8_t> data;
        uint64_t timestamp_ms;
        bool keyframe;
    };


    class RtspIngestSession
    {
    public:
        RtspIngestSession(std::string id, std::string url) : id_(std::move(id)), url_(std::move(url)) {}

        void Start() {
            running_ = true;
            thread_ = std::thread(&RtspIngestSession::Loop, this);
        }

        void Stop() {
            running_ = false;
            if (thread_.joinable()) thread_.join();
        }

        void AddSubscriber(std::shared_ptr<grpc::ServerWriter<iar::rpc::StreamChunk>> writer)
        {
            std::lock_guard<std::mutex> lock(mu_);
            subscribers_.push_back(writer);
        }

        void EnableRecording(const std::string& path) {
            //recording_ = std::make_unique<RecordingSession>(path);
        }

        void DisableRecording() {
            recording_.reset();
        }

    private:
        void Loop() {
            // --- FFmpeg setup (simplified) ---
            AVFormatContext* fmt = nullptr;
            avformat_open_input(&fmt, url_.c_str(), nullptr, nullptr);
            avformat_find_stream_info(fmt, nullptr);

            AVPacket pkt;
            while (running_ && av_read_frame(fmt, &pkt) >= 0) {
                EncodedPacket p;
                p.data.assign(pkt.data, pkt.data + pkt.size);
                p.timestamp_ms = pkt.pts;
                p.keyframe = pkt.flags & AV_PKT_FLAG_KEY;

                Broadcast(p);
                av_packet_unref(&pkt);
            }

            avformat_close_input(&fmt);
        }

        void Broadcast(const EncodedPacket& p) {
            // Send to subscribers
            {
                std::lock_guard<std::mutex> lock(mu_);
                for (auto& w : subscribers_) {
                    iar::rpc::StreamChunk chunk;
                    chunk.set_data(p.data.data(), p.data.size());
                    chunk.set_timestamp_ms(p.timestamp_ms);
                    chunk.set_keyframe(p.keyframe);
                    w->Write(chunk);
                }
            }

            // Send to recorder
            if (recording_) {
                //recording_->Write(p);
            }
        }

    private:
        std::string id_;
        std::string url_;
        std::atomic<bool> running_{false};
        std::thread thread_;

        std::mutex mu_;
        std::vector<std::shared_ptr<grpc::ServerWriter<iar::rpc::StreamChunk>>> subscribers_;

        std::unique_ptr<RecordingSession> recording_;
    };

} }