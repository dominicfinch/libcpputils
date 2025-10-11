
#include "hash_tests.h"
#include "hash.h"

bool test_hash_md5() {
    iar::utils::HASH hash;
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::string target_output = "9e107d9d372bb6826bd81d3542a419d6";
    std::string output;

    if (!hash.digest(input, output, "md5")) return false;
    return output == target_output;
}

bool test_hash_sha256() {
    iar::utils::HASH hash;
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::string target_output = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
    std::string output;

    if (!hash.digest(input, output, "sha256")) return false;
    return output == target_output;
}

bool test_hash_sha384() {
    iar::utils::HASH hash;
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::string target_output = "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1";
    std::string output;

    if (!hash.digest(input, output, "sha384")) return false;
    return output == target_output;
}

bool test_hash_sha512() {
    iar::utils::HASH hash;
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::string target_output = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6";
    std::string output;

    if (!hash.digest(input, output, "sha512")) return false;
    return output == target_output;
}