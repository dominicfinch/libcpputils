
#include "b58_tests.h"
#include "base58.h"

bool test_base58_encode_decode() {
    std::vector<uint8_t> original_data = {
        0x00, 0x00, 0x01, 0x02, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    };

    std::string encoded = iar::utils::Base58::encode(original_data);
    std::vector<uint8_t> decoded;
    try {
        decoded = iar::utils::Base58::decode(encoded);
    } catch (const std::exception& e) {
        return false;
    }

    if (decoded.size() != original_data.size()) {
        return false;
    }

    for (size_t i = 0; i < original_data.size(); ++i) {
        if (decoded[i] != original_data[i]) {
            return false;
        }
    }
    return true;
}