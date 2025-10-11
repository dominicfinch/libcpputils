
#ifndef IAR_UTILS_HEX_H
#define IAR_UTILS_HEX_H

#include <string>
#include <vector>
#include <cstdint>

namespace iar { namespace utils {

    class Hex {
    public:
        static std::string encode(std::vector<uint8_t>& input);
        static std::vector<uint8_t> decode(const std::string& hex);

        static bool encode(const std::string& input, std::string& output);
        static bool decode(const std::string& input, std::string& output);
    };
}}


#endif
