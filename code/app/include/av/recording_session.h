#pragma once

#include <memory>
#include <vector>
#include <mutex>

#include "interfaces/storage.h"


namespace iar { namespace av {

class cloud_storage_sink;

class RecordingSession {
public:
    explicit RecordingSession(std::unique_ptr<cloud_storage_sink> sink) : _sink(std::move(sink)) {}

    bool start(const std::string& object_name) {
        return _sink->open(object_name);
    }

    void write_packet(const uint8_t* data, size_t size) {
        std::lock_guard<std::mutex> lock(_mutex);
        _sink->write(data, size);
    }

    void stop() {
        std::lock_guard<std::mutex> lock(_mutex);
        _sink->close();
    }

    std::string uri() const {
        return _sink->object_uri();
    }

private:
    std::unique_ptr<cloud_storage_sink> _sink;
    std::mutex _mutex;
};

} }