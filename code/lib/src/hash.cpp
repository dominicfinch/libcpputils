
#include "hash.h"

#include <cstring>
#include <sstream>
#include <openssl/sha.h>

namespace iar {
    namespace utils {

        bool HASH::digest(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const std::string& algo) {
            bool success = false;

            EVP_MD_CTX* ctx = EVP_MD_CTX_create();
            if (ctx != nullptr) {
                auto algo_struct = EVP_get_digestbyname(algo.c_str());
                if (algo_struct != nullptr) {
                    unsigned int digestLen = EVP_MD_size(algo_struct);
                    if (EVP_DigestInit_ex(ctx, algo_struct, nullptr) > 0) {
                        if (EVP_DigestUpdate(ctx, input.data(), input.size()) > 0) {
                            uint8_t buffer[EVP_MAX_MD_SIZE];
                            if (EVP_DigestFinal_ex(ctx, &buffer[0], &digestLen) > 0) {
                                output.clear();
                                output.insert(output.begin(), buffer, buffer + digestLen);
                                success = true;
                            }
                        }
                    }
                }
                else {
                    printf(" - Error: Unsupported hash algorithm");
                }
            }
            EVP_MD_CTX_destroy(ctx);
            return success;
        }

        bool HASH::digest(const std::string& input, std::string& output, const std::string& algo) {
            std::vector<uint8_t> uc_input(input.begin(), input.end()), uc_output;
            auto digestSuccess = digest(uc_input, uc_output, algo);

            std::stringstream ss;
            for (auto ch : uc_output) {
                char data[3] = { '\0' };
                snprintf(data, sizeof(data), "%02x", (int)ch);
                ss << data;
            }

            output = ss.str();
            return digestSuccess;
        }
    }
}