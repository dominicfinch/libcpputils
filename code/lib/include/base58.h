#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "macros.h"

namespace iar { namespace utils {

    class Base58 {
        public:
            static std::string encode(const std::vector<uint8_t>& input);
            static std::vector<uint8_t> decode(const std::string& input);

        private:
            static constexpr const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    };
}}