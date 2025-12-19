
#include "trust_store.h"

#include <openssl/pem.h>
#include <openssl/err.h>

namespace iar { namespace utils {

TrustStore::TrustStore()
    : store_(X509_STORE_new())
{
}

TrustStore::~TrustStore()
{
    if (store_) {
        X509_STORE_free(store_);
        store_ = nullptr;
    }
}

void TrustStore::clear()
{
    certs_.clear();
    if (store_) {
        X509_STORE_free(store_);
        store_ = X509_STORE_new();
    }
}

bool TrustStore::add_certificate(const Certificate& cert)
{
    if (!cert.raw()) return false;
    certs_.push_back(cert);
    return rebuild_store();
}

bool TrustStore::remove_certificate_by_fingerprint(const std::string& fingerprint_hex)
{
    for (auto it = certs_.begin(); it != certs_.end(); ++it) {
        std::vector<uint8_t> fingerprint;
        it->fingerprint_sha256(fingerprint);
        //if (fingerprint == fingerprint_hex) {
        //    certs_.erase(it);
        //    return rebuild_store();
        //}
    }
    return false;
}

Certificate* TrustStore::find_by_subject(const std::string& subject_dn)
{
    for (auto& cert : certs_) {
        //if (cert.subject_dn() == subject_dn)
        //    return &cert;
    }
    return nullptr;
}

Certificate* TrustStore::find_by_fingerprint(const std::string& fingerprint_hex)
{
    for (auto& cert : certs_) {
        //if (cert.fingerprint_sha256() == fingerprint_hex)
        //    return &cert;
    }
    return nullptr;
}

std::vector<Certificate> TrustStore::all_certificates() const
{
    return certs_;
}

bool TrustStore::verify_certificate(const Certificate& cert)
{
    if (!store_ || !cert.raw()) return false;

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) return false;

    if (X509_STORE_CTX_init(ctx, store_, cert.raw(), nullptr) != 1) {
        X509_STORE_CTX_free(ctx);
        return false;
    }

    int rc = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    return rc == 1;
}

bool TrustStore::verify_chain(const std::vector<Certificate>& chain)
{
    if (chain.empty() || !store_) return false;

    STACK_OF(X509)* untrusted = sk_X509_new_null();
    if (!untrusted) return false;

    for (size_t i = 1; i < chain.size(); ++i) {
        sk_X509_push(untrusted, chain[i].raw());
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        sk_X509_free(untrusted);
        return false;
    }

    if (X509_STORE_CTX_init(ctx, store_, chain[0].raw(), untrusted) != 1) {
        X509_STORE_CTX_free(ctx);
        sk_X509_free(untrusted);
        return false;
    }

    int rc = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    sk_X509_free(untrusted);
    return rc == 1;
}

bool TrustStore::load_ca_file(const std::string& path)
{
    if (!store_) return false;
    return X509_STORE_load_locations(store_, path.c_str(), nullptr) == 1;
}

bool TrustStore::load_ca_directory(const std::string& path)
{
    if (!store_) return false;
    return X509_STORE_load_locations(store_, nullptr, path.c_str()) == 1;
}

bool TrustStore::export_trust_store_pem(const std::string& path) const
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;

    for (const auto& cert : certs_) {
        if (!PEM_write_X509(f, cert.raw())) {
            fclose(f);
            return false;
        }
    }

    fclose(f);
    return true;
}

bool TrustStore::rebuild_store()
{
    if (store_) {
        X509_STORE_free(store_);
    }
    store_ = X509_STORE_new();
    if (!store_) return false;

    for (const auto& cert : certs_) {
        if (!cert.raw()) continue;
        if (X509_STORE_add_cert(store_, cert.raw()) != 1) {
            // Duplicate certs are OK
            unsigned long err = ERR_peek_last_error();
            if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
                return false;
        }
    }
    return true;
}

} } // namespace iar::crypto
