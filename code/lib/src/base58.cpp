
#include "base58.h"
#include <algorithm>
#include <stdexcept>
#include <unordered_map>

namespace iar { namespace utils {

    std::string Base58::encode(const std::vector<uint8_t>& input) {
        if (input.empty()) return "";

        // Count leading zeros
        size_t zero_count = 0;
        while (zero_count < input.size() && input[zero_count] == 0) {
            zero_count++;
        }

        // Convert bytes to big integer
        std::vector<uint8_t> temp(input.begin(), input.end());

        std::string result;

        // Convert big endian bytes to base58 string
        // Use a "divmod" approach:
        std::vector<uint8_t> digits; // will hold base58 digits in reverse order
        digits.push_back(0);

        for (size_t i = zero_count; i < temp.size(); ++i) {
            int carry = temp[i];
            for (auto& digit : digits) {
                carry += digit << 8;  // digit * 256
                digit = carry % 58;
                carry /= 58;
            }

            while (carry > 0) {
                digits.push_back(carry % 58);
                carry /= 58;
            }
        }

        // Leading zeros correspond to '1' in base58
        for (size_t i = 0; i < zero_count; ++i) {
            result += '1';
        }

        // Convert digits to string (digits are reversed)
        for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
            result += BASE58_ALPHABET[*it];
        }

        return result;
    }

    std::vector<uint8_t> Base58::decode(const std::string& input) {
        if (input.empty()) return {};

        // Build map of char to index in base58 alphabet
        std::unordered_map<char, int> alphabet_index;
        for (int i = 0; BASE58_ALPHABET[i] != '\0'; ++i) {
            alphabet_index[BASE58_ALPHABET[i]] = i;
        }

        // Count leading '1's which are leading zeros
        size_t zero_count = 0;
        while (zero_count < input.size() && input[zero_count] == '1') {
            zero_count++;
        }

        std::vector<uint8_t> bytes; // decoded bytes, little-endian

        for (size_t i = zero_count; i < input.size(); ++i) {
            auto it = alphabet_index.find(input[i]);
            if (it == alphabet_index.end()) {
                throw std::runtime_error("Invalid character in Base58 string");
            }
            int carry = it->second;

            for (auto& byte : bytes) {
                carry += byte * 58;
                byte = carry & 0xFF;
                carry >>= 8;
            }

            while (carry > 0) {
                bytes.push_back(carry & 0xFF);
                carry >>= 8;
            }
        }

        // Append leading zeros (corresponding to leading '1's)
        for (size_t i = 0; i < zero_count; ++i) {
            bytes.push_back(0);
        }

        // The bytes are in little endian, reverse to big endian
        std::reverse(bytes.begin(), bytes.end());

        return bytes;
    }

}}