
#pragma once

#include <string>
#include <chrono>
#include <optional>

namespace iar { namespace sql {
    
    struct VideoObject {
        std::string id;
        std::string recording_id;
        std::string object_path;
        std::string format;
        int64_t size_bytes;
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point end_time;
        std::chrono::system_clock::time_point created_at;
    };


    
} }