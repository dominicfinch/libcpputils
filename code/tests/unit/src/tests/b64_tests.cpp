#include "b64_tests.h"
#include "base64.h"

bool test_base64_encode_decode() {
    std::string input = "This is a test string!";
    std::string target_output = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ==";
    std::string output, decoded;

    if(!iar::utils::Base64::encode(input, output)) return false;
    if(output != target_output) return false;
    if(!iar::utils::Base64::decode(output, decoded)) return false;

    return decoded == input;
}