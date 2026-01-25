#pragma once

#include <functional>
#include <mutex>
#include <vector>

extern "C" {
#include <libavcodec/packet.h>
}

namespace iar { namespace av {

    class PacketBroadcaster {
    public:
    using Subscriber = std::function<void(const AVPacket&)>;

    void subscribe(Subscriber sub);
    void broadcast(const AVPacket& pkt);

    private:
    std::mutex mutex_;
    std::vector<Subscriber> subscribers_;
    };

} }