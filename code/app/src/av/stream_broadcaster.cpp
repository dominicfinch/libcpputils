
#include "av/stream_broadcaster.h"

/*
void iar::av::StreamBroadcaster::subscribe(iar::av::StreamBroadcaster::Subscriber sub)
{
    std::lock_guard lock(mutex_);
    subscribers_.push_back(std::move(sub));
}

void iar::av::StreamBroadcaster::broadcast(const AVPacket& pkt)
{
    std::lock_guard lock(mutex_);
    for (auto& s : subscribers_) {
        s(pkt);
    }
}
*/
