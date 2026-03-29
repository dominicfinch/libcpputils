#pragma once

#include <string>
#include <vector>
#include <memory>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "certificate.h"

namespace cpp { namespace utils {

//class Certificate;

/**
 * P12Repository
 *
 * High-level PKCS#12 container manager.
 * Owns keys + certificates and allows inspection, modification,
 * and persistence to disk.
 */
class P12Repository {
public:
    P12Repository();
    ~P12Repository();

    // Non-copyable
    P12Repository(const P12Repository&) = delete;
    P12Repository& operator=(const P12Repository&) = delete;

    // Movable
    P12Repository(P12Repository&&) noexcept;
    P12Repository& operator=(P12Repository&&) noexcept;

    // Load / Save
    bool load_from_file(const std::string& path, const std::string& password);
    bool save_to_file(const std::string& path, const std::string& password) const;

    // Clear repository
    void clear();

    // Key handling
    bool has_private_key() const;
    EVP_PKEY* get_private_key() const;
    bool set_private_key(EVP_PKEY* key); // takes ownership
    void remove_private_key();

    // Certificate handling
    size_t certificate_count() const;
    std::shared_ptr<Certificate> get_certificate(size_t index) const;
    std::vector<std::shared_ptr<Certificate>> get_all_certificates() const;

    void add_certificate(const std::shared_ptr<Certificate>& cert);
    bool remove_certificate(size_t index);

    // Leaf certificate helpers
    std::shared_ptr<Certificate> get_leaf_certificate() const;
    void set_leaf_certificate(const std::shared_ptr<Certificate>& cert);

    // Debug / inspection
    std::string describe() const;

private:
    EVP_PKEY* private_key_;
    std::vector<std::shared_ptr<Certificate>> certificates_;
    std::shared_ptr<Certificate> leaf_cert_;

    // Helpers
    static X509* cert_to_x509(const Certificate& cert);
};

} } // namespace cpp::utils
