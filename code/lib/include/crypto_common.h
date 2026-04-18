#pragma once

#include <vector>
#include <memory>
#include <string>
#include <functional>

namespace cpp { namespace utils {

using PasswordCallback = std::function<std::string()>;

struct PasswordCallbackWrapper {
    PasswordCallback cb;
};

bool hkdf_sha256(const std::vector<uint8_t>&salt,
                        const std::vector<uint8_t>&ikm,
                        const std::vector<uint8_t>&info,
                        std::vector<uint8_t>&okm,
                        size_t L);

int openssl_password_cb(char* buf, int size, int, void* userdata);

} }