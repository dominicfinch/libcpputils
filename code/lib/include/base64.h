
#ifndef IAR_UTILS_BASE64_H
#define IAR_UTILS_BASE64_H

#include <string>
#include <vector>
#include <cstdint>

namespace iar { namespace utils {

    class Base64 {

    public:

        static bool encode(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
        static bool decode(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);

        static bool encode(const std::string& input, std::string& output);
        static bool decode(const std::string& input, std::string& output);

        static std::string encode(const std::vector<uint8_t>& input);
        static std::vector<uint8_t> decode(const std::string& input);
    };

}}

#endif
