#pragma once

#include <openssl/evp.h>
#include <string>
#include <vector>

namespace iar { namespace utils {

class Certificate; // forward declaration

class PrivateKey
{
public:
    PrivateKey();
    explicit PrivateKey(EVP_PKEY* pkey);   // takes ownership
    ~PrivateKey();

    // Non-copyable, movable
    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    PrivateKey(PrivateKey&& other) noexcept;
    PrivateKey& operator=(PrivateKey&& other) noexcept;

    // Load / Save
    bool load_pem(const std::string& path, const std::string& password = "");
    bool save_pem(const std::string& path, const std::string& password = "") const;

    bool load_der(const std::string& path);
    bool save_der(const std::string& path) const;

    // In-memory PEM
    bool from_pem_string(const std::string& pem, const std::string& password = "");
    bool to_pem_string(std::string& pem, const std::string& password = "") const;

    // Key generation
    static PrivateKey generate_rsa(int bits = 2048);
    static PrivateKey generate_ec(const std::string& curve = "prime256v1");
    static PrivateKey generate_ed25519();

    // Inspection
    bool is_valid() const;
    int  key_type() const;
    int  key_bits() const;

    std::string key_type_name() const;

    // Raw access (advanced use)
    EVP_PKEY* get() const;

    // Certificate binding helper
    bool matches_certificate(const Certificate& cert) const;

private:
    EVP_PKEY* pkey_;

    static int password_cb(char* buf, int size, int rwflag, void* userdata);
};

} } // namespace iar::crypto
