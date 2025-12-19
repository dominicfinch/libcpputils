
// PKCS12Manager.cpp
#include "pkcs12_manager.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

#include <fstream>
#include <sstream>
#include <cstring>

namespace iar { namespace utils {

static void free_pkey(EVP_PKEY*& p) { if (p) { EVP_PKEY_free(p); p = nullptr; } }
static void free_x509(X509*& x) { if (x) { X509_free(x); x = nullptr; } }
static void free_stack_x509(STACK_OF(X509)*& sk) { if (sk) { sk_X509_pop_free(sk, X509_free); sk = nullptr; } }

PKCS12Manager::PKCS12Manager() : pkey_(nullptr), cert_(nullptr), ca_(nullptr) {}
PKCS12Manager::~PKCS12Manager() { clear(); }

PKCS12Manager::PKCS12Manager(PKCS12Manager&& o) noexcept
    : pkey_(o.pkey_), cert_(o.cert_), ca_(o.ca_)
{
    o.pkey_ = nullptr;
    o.cert_ = nullptr;
    o.ca_ = nullptr;
}

PKCS12Manager& PKCS12Manager::operator=(PKCS12Manager&& o) noexcept {
    if (this != &o) {
        clear();
        pkey_ = o.pkey_; cert_ = o.cert_; ca_ = o.ca_;
        o.pkey_ = nullptr; o.cert_ = nullptr; o.ca_ = nullptr;
    }
    return *this;
}

std::string PKCS12Manager::openssl_errors() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string s;
    if (bptr && bptr->length > 0) s.assign(bptr->data, bptr->length);
    BIO_free(bio);
    return s;
}

// Load from file
bool PKCS12Manager::load_from_file(const std::string& path, const std::string& password) {
    clear();
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    PKCS12* p12 = d2i_PKCS12_fp(f, nullptr);
    fclose(f);
    if (!p12) return false;

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    int ok = PKCS12_parse(p12, password.empty() ? nullptr : password.c_str(), &pkey, &cert, &ca);
    PKCS12_free(p12);
    if (!ok) {
        // parsing failed
        free_pkey(pkey); free_x509(cert); free_stack_x509(ca);
        return false;
    }

    // replace internals
    pkey_ = pkey;
    cert_ = cert;
    ca_ = ca;
    return true;
}

// Load from memory (DER bytes)
bool PKCS12Manager::load_from_memory(const std::vector<uint8_t>& data, const std::string& password) {
    clear();
    BIO* bio = BIO_new_mem_buf(data.data(), (int)data.size());
    if (!bio) return false;
    PKCS12* p12 = d2i_PKCS12_bio(bio, nullptr);
    BIO_free(bio);
    if (!p12) return false;

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    int ok = PKCS12_parse(p12, password.empty() ? nullptr : password.c_str(), &pkey, &cert, &ca);
    PKCS12_free(p12);
    if (!ok) {
        free_pkey(pkey); free_x509(cert); free_stack_x509(ca);
        return false;
    }
    pkey_ = pkey;
    cert_ = cert;
    ca_ = ca;
    return true;
}

// Save to file
bool PKCS12Manager::save_to_file(const std::string& path, const std::string& password,
                                 const std::string& friendly_name, int iterations, int mac_iter)
{
    // Build PKCS12 structure
    // If there's no cert or no key, we can still create a PKCS12 with cert or empty; but typically user will have both.
    PKCS12* p12 = PKCS12_create(password.empty() ? nullptr : password.c_str(),
                                friendly_name.empty() ? nullptr : friendly_name.c_str(),
                                pkey_, cert_, ca_,
                                0, /* nid_key - default */
                                0, /* nid_cert */
                                iterations /* iter */ , mac_iter /* mac_iter */, KEY_EX /* 0, KEY_SIG  */);
    if (!p12) return false;

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { PKCS12_free(p12); return false; }
    int rc = i2d_PKCS12_fp(f, p12);
    fclose(f);
    PKCS12_free(p12);
    return rc == 1;
}

// Save to memory DER
bool PKCS12Manager::save_to_memory(std::vector<uint8_t>& out, const std::string& password,
                                   const std::string& friendly_name, int iterations, int mac_iter)
{
    out.clear();
    PKCS12* p12 = PKCS12_create(password.empty() ? nullptr : password.c_str(),
                                friendly_name.empty() ? nullptr : friendly_name.c_str(),
                                pkey_, cert_, ca_,
                                0, 0, iterations, mac_iter, KEY_EX /* 0, KEY_SIG  */);
    if (!p12) return false;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) { PKCS12_free(p12); return false; }

    if (i2d_PKCS12_bio(bio, p12) != 1) {
        PKCS12_free(p12);
        BIO_free(bio);
        return false;
    }

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    if (bptr && bptr->length > 0) {
        out.resize(bptr->length);
        memcpy(out.data(), bptr->data, bptr->length);
    }
    PKCS12_free(p12);
    BIO_free(bio);
    return !out.empty();
}

// Accessors
EVP_PKEY* PKCS12Manager::get_private_key() const { return pkey_; }
X509* PKCS12Manager::get_certificate() const { return cert_; }
STACK_OF(X509)* PKCS12Manager::get_ca_chain() const { return ca_; }

// Setters (take ownership)
void PKCS12Manager::set_private_key(EVP_PKEY* pkey) {
    free_pkey(pkey_);
    pkey_ = pkey;
}
void PKCS12Manager::set_certificate(X509* cert) {
    free_x509(cert_);
    cert_ = cert;
}
void PKCS12Manager::set_ca_chain(STACK_OF(X509)* ca) {
    free_stack_x509(ca_);
    ca_ = ca;
}

// Export private key PEM
bool PKCS12Manager::export_private_key_pem(std::string& pem) const {
    pem.clear();
    if (!pkey_) return false;
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    if (!PEM_write_bio_PrivateKey(bio, pkey_, nullptr, nullptr, 0, nullptr, nullptr)) { BIO_free(bio); return false; }
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    if (bptr && bptr->length > 0) pem.assign(bptr->data, bptr->length);
    BIO_free(bio);
    return !pem.empty();
}

// Export certificate PEM
bool PKCS12Manager::export_certificate_pem(std::string& pem) const {
    pem.clear();
    if (!cert_) return false;
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    if (!PEM_write_bio_X509(bio, cert_)) { BIO_free(bio); return false; }
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    if (bptr && bptr->length > 0) pem.assign(bptr->data, bptr->length);
    BIO_free(bio);
    return !pem.empty();
}

// Import private key PEM (ownership transferred to manager)
bool PKCS12Manager::import_private_key_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return false;
    EVP_PKEY* p = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!p) return false;
    set_private_key(p);
    return true;
}

// Import certificate PEM
bool PKCS12Manager::import_certificate_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return false;
    X509* x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!x) return false;
    set_certificate(x);
    return true;
}

void PKCS12Manager::clear() {
    free_pkey(pkey_);
    free_x509(cert_);
    free_stack_x509(ca_);
}

std::string PKCS12Manager::describe() const {
    std::ostringstream oss;
    oss << "PKCS12Manager{";
    oss << "has_private=" << (pkey_ ? "yes" : "no");
    oss << ", has_cert=" << (cert_ ? "yes" : "no");
    oss << ", ca_count=";
    if (!ca_) oss << 0;
    else oss << sk_X509_num(ca_);
    oss << "}";
    return oss.str();
}

}}