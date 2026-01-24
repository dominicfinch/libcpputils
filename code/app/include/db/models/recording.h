
#pragma once

#include <string>
#include <chrono>
#include <optional>

namespace iar { namespace sql {
    
    struct Recording {
        std::string id;
        std::string stream_id;
        std::string storage_id;
        std::chrono::system_clock::time_point start_time;
        std::optional<std::chrono::system_clock::time_point> end_time;
        std::string status;
        std::chrono::system_clock::time_point created_at;
    };
    
} }
