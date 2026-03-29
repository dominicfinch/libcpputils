#pragma once

#include <openssl/x509v3.h>
#include <string>
#include <vector>

namespace cpp { namespace utils {

class Certificate {
public:
    Certificate();
    explicit Certificate(X509* cert);
    Certificate(const Certificate&);

    Certificate& operator=(const Certificate& other);
    //Certificate& operator=(Certificate&& other) noexcept;
    
    Certificate(Certificate&& other) noexcept;
    ~Certificate();

    bool load_from_pem(const std::string& pem);
    bool as_pem(std::string& output) const;

    bool load_pem_file(const std::string& path);
    bool save_pem_file(const std::string& path) const;

    bool load_der_file(const std::string& path);
    bool save_der_file(const std::string& path) const;

    std::string subject() const;
    //std::string subject_dn() const;
    std::string issuer() const;
    std::string serial() const;
    std::string common_name() const;

    bool is_ca() const;
    bool is_self_signed() const;

    bool get_common_name(std::string& cn) const;
    bool verify(const Certificate& issuer) const;

    time_t not_before() const;
    time_t not_after() const;
    bool is_valid_now() const;
    bool fingerprint_sha256(std::vector<uint8_t>& out) const;

    EVP_PKEY* extract_public_key() const;
    X509* raw() const { return cert_; }

private:

    static time_t ASN1_TIME_get(const ASN1_TIME* time);
    X509* cert_;
};

} }