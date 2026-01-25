
#include "av/rtsp_injest_session.h"
#include <iostream>

namespace iar { namespace av {

    RtspIngestSession::RtspIngestSession(std::string rtsp_url): rtsp_url_(std::move(rtsp_url)) {}

    RtspIngestSession::~RtspIngestSession() {
        stop();
    }

    bool RtspIngestSession::start() {
        avformat_network_init();

        AVDictionary* opts = nullptr;
        av_dict_set(&opts, "rtsp_transport", "tcp", 0);
        av_dict_set(&opts, "stimeout", "5000000", 0);

        if (avformat_open_input(&fmt_ctx_, rtsp_url_.c_str(), nullptr, &opts) != 0) {
            std::cerr << "Failed to open RTSP: " << rtsp_url_ << "\n";
            return false;
        }

        if (avformat_find_stream_info(fmt_ctx_, nullptr) < 0) {
            std::cerr << "Failed to read stream info\n";
            return false;
        }

        running_ = true;
        worker_ = std::thread(&RtspIngestSession::ingest_loop, this);
        return true;
    }

    void RtspIngestSession::stop() {
        running_ = false;
        if (worker_.joinable()) worker_.join();

        if (fmt_ctx_) {
            avformat_close_input(&fmt_ctx_);
            fmt_ctx_ = nullptr;
        }
    }

    void RtspIngestSession::set_packet_callback(PacketCallback cb) {
        packet_cb_ = std::move(cb);
    }

    void RtspIngestSession::ingest_loop() {
        AVPacket pkt;
        av_init_packet(&pkt);

        while (running_) {
            if (av_read_frame(fmt_ctx_, &pkt) == 0) {
            if (packet_cb_) {
                packet_cb_(pkt); // no decode!
            }
            av_packet_unref(&pkt);
            }
        }
    }


}}