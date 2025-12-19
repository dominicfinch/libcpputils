
#pragma once
// PKCS12Manager.hpp
// Simple PKCS#12 loader / saver / manipulator for OpenSSL 3.0+
//
// Usage:
//   PKCS12Manager m;
//   if (!m.load_from_file("bundle.p12", "password")) { ... }
//   EVP_PKEY* key = m.get_private_key(); // borrowed pointer
//   X509* cert = m.get_certificate();
//   m.save_to_file("out.p12", "newpass");
//
// Memory ownership:
//   get_private_key/get_certificate return borrowed pointers (do not free).
//   The manager owns and frees its internal OpenSSL objects on destruction.

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include <string>
#include <vector>

namespace iar { namespace utils {

class PKCS12Manager {
public:
    PKCS12Manager();
    ~PKCS12Manager();

    // Non-copyable
    PKCS12Manager(const PKCS12Manager&) = delete;
    PKCS12Manager& operator=(const PKCS12Manager&) = delete;

    // Movable
    PKCS12Manager(PKCS12Manager&&) noexcept;
    PKCS12Manager& operator=(PKCS12Manager&&) noexcept;

    // Load / Save
    bool load_from_file(const std::string& path, const std::string& password);
    bool load_from_memory(const std::vector<uint8_t>& data, const std::string& password);

    // Save PKCS#12 to file or memory. friendly_name may be empty.
    // iterations: PKCS12 PBKDF iteration count (0 -> use OpenSSL default)
    bool save_to_file(const std::string& path, const std::string& password,
                      const std::string& friendly_name = "", int iterations = 0, int mac_iter = 0);
    bool save_to_memory(std::vector<uint8_t>& out, const std::string& password,
                        const std::string& friendly_name = "", int iterations = 0, int mac_iter = 0);

    // Accessors (borrowed pointers; do NOT free them)
    EVP_PKEY* get_private_key() const;
    X509* get_certificate() const;
    STACK_OF(X509)* get_ca_chain() const;

    // Replace internals (manager will own these after set)
    // If non-null, ownership transfers to manager (it will free on destruction or next set)
    void set_private_key(EVP_PKEY* pkey);
    void set_certificate(X509* cert);
    void set_ca_chain(STACK_OF(X509)* ca);

    // PEM import/export helpers
    bool export_private_key_pem(std::string& pem) const;
    bool export_certificate_pem(std::string& pem) const;
    bool import_private_key_pem(const std::string& pem);
    bool import_certificate_pem(const std::string& pem);

    // Clear internal state (frees current objects)
    void clear();

    // Info helper
    std::string describe() const;

private:
    EVP_PKEY* pkey_;         // private key (may be null)
    X509* cert_;             // leaf certificate (may be null)
    STACK_OF(X509)* ca_;     // CA chain (may be null)

    // helpers
    static std::string openssl_errors();
};

}}