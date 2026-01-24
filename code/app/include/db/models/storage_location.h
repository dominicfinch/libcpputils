
#pragma once

#include <string>
#include <chrono>
#include <optional>

namespace iar { namespace sql {
    
    struct StorageLocation {
        std::string id;
        std::string provider;
        std::string bucket;
        std::string prefix;
        std::string region;
        std::chrono::system_clock::time_point created_at;
    };

    
} }