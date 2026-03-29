#pragma once

#include <vector>
#include <memory>

namespace cpp { namespace utils {

bool hkdf_sha256(const std::vector<uint8_t>&salt,
                        const std::vector<uint8_t>&ikm,
                        const std::vector<uint8_t>&info,
                        std::vector<uint8_t>&okm,
                        size_t L);

} }