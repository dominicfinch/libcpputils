
#include "hex.h"
#include <sstream>

namespace iar { namespace utils {

    std::string Hex::encode(std::vector<uint8_t>& input) {
        static const char* hex_digits = "0123456789abcdef";
        std::string hex;
        hex.reserve(input.size() * 2);
        for (auto byte : input) {
            hex.push_back(hex_digits[byte >> 4]);
            hex.push_back(hex_digits[byte & 0x0F]);
        }
        return hex;
    }

    std::vector<uint8_t> Hex::decode(const std::string& hex) {
        if (hex.length() % 2 != 0) {
            throw std::invalid_argument("Hex string must have even length");
        }

        std::vector<uint8_t> bytes;
        bytes.reserve(hex.length() / 2);

        auto hex_char_to_value = [](char c) -> uint8_t {
            if (std::isdigit(c)) return c - '0';
            if (std::isxdigit(c)) return std::tolower(c) - 'a' + 10;
            throw std::invalid_argument("Invalid hex character");
        };

        for (size_t i = 0; i < hex.length(); i += 2) {
            char high = hex[i];
            char low = hex[i + 1];
            uint8_t byte = (hex_char_to_value(high) << 4) | hex_char_to_value(low);
            bytes.push_back(byte);
        }

        return bytes;
    }

    bool Hex::encode(const std::string& input, std::string& output) {
        output.clear();
        std::stringstream ss;
        for(auto& ch : input) {
            ss << std::hex << (int)ch;
        }
        output = ss.str();
        return output.size() != 0;
    }

    bool Hex::decode(const std::string& input, std::string& output) {
        std::stringstream ss;
        if(input.size() % 2 == 0) {     // Every two characters make up 1 ASCII character
            std::string part; char ch;
            for(auto i = 0; i < input.size(); i += 2) {
                part = input.substr(i, 2);
                ch = stoul(part, nullptr, 16);
                ss << ch;
            }
        }
        output = ss.str();
        return output.size() != 0;
    }

}}
