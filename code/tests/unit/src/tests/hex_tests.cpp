#include "hex_tests.h"
#include "hex.h"

bool test_hex_encode_decode() {
    std::string input = "This is a test string!";
    std::string target_output = "546869732069732061207465737420737472696e6721";
    std::string output, decoded;

    if(!iar::utils::Hex::encode(input, output)) return false;
    if(output != target_output) return false;
    if(!iar::utils::Hex::decode(output, decoded)) return false;

    return decoded == input;
}