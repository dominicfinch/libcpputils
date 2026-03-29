/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace cpp { namespace utils {

    class Hex {
    public:
        static std::string encode(std::vector<uint8_t>& input);
        static std::vector<uint8_t> decode(const std::string& hex);

        static bool encode(const std::string& input, std::string& output);
        static bool decode(const std::string& input, std::string& output);
    };
}}
