#pragma once

#include <vector>
#include <string>
#include <memory>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "certificate.h"

namespace iar { namespace utils {

class TrustStore {
public:
    TrustStore();
    ~TrustStore();

    // ------------------------------
    // Certificate management
    // ------------------------------
    bool add_certificate(const Certificate& cert);
    bool remove_certificate_by_fingerprint(const std::string& fingerprint_hex);

    bool load_ca_file(const std::string& path);
    bool load_ca_directory(const std::string& path);

    void clear();

    // ------------------------------
    // Lookup
    // ------------------------------
    Certificate* find_by_subject(const std::string& subject_dn);
    Certificate* find_by_fingerprint(const std::string& fingerprint_hex);

    std::vector<Certificate> all_certificates() const;

    // ------------------------------
    // Trust verification
    // ------------------------------
    bool verify_certificate(const Certificate& cert);
    bool verify_chain(const std::vector<Certificate>& chain);

    // ------------------------------
    // Export
    // ------------------------------
    bool export_trust_store_pem(const std::string& path) const;

private:
    TrustStore(const TrustStore&) = delete;
    TrustStore& operator=(const TrustStore&) = delete;

    bool rebuild_store();

    X509_STORE* store_;
    std::vector<Certificate> certs_;
};

} } // namespace iar::crypto
