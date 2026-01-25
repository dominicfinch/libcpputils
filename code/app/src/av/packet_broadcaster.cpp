
#include "av/packet_broadcaster.h"

void iar::av::PacketBroadcaster::subscribe(iar::av::PacketBroadcaster::Subscriber sub) {
  std::lock_guard lock(mutex_);
  subscribers_.push_back(std::move(sub));
}

void iar::av::PacketBroadcaster::broadcast(const AVPacket& pkt) {
  std::lock_guard lock(mutex_);
  for (auto& s : subscribers_) {
    s(pkt);
  }
}
