#pragma once

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>

namespace iar::utils {

class ECDSA {
public:
    ECDSA();
    ~ECDSA();

    bool generate_keypair(int bits = 384);
    bool export_public_key(const std::string& path);
    bool export_private_key(const std::string& path);
    bool import_private_key(const std::string& path);
    bool import_public_key(const std::string& path);

    bool sign(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature, const std::string& hash = "SHA384");
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::string& hash = "SHA384");

private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_;
    static std::string get_openssl_error();
};

} // namespace iar::utils
