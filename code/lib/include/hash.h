
#pragma once

#include <string>
#include <vector>
#include <openssl/evp.h>

namespace iar {
    namespace utils {

        class HASH {
        public:
            bool digest(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const std::string& algo = "sha256");
            bool digest(const std::string& input, std::string& output, const std::string& algo = "sha256");
        };
    }
}