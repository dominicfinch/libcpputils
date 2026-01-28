#pragma once

#include <string>
#include <vector>
#include <cstdint>


namespace iar { namespace app {

class cloud_storage_sink {
public:
    virtual ~cloud_storage_sink() = default;

    // Called once per recording session
    virtual bool open(const std::string& object_name) = 0;

    // Called repeatedly with encoded video data
    virtual bool write(const uint8_t* data, size_t size) = 0;

    // Called when recording stops
    virtual bool close() = 0;

    // Optional metadata (DB, logs, etc.)
    virtual std::string object_uri() const = 0;
};

} }