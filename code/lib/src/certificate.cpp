
#include "certificate.h"

#include <time.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <ctime>

namespace iar { namespace utils {

Certificate::Certificate() : cert_(nullptr) {}

Certificate::~Certificate() {
    if (cert_) X509_free(cert_);
}

Certificate::Certificate(const Certificate& other) {
    cert_ = other.cert_ ? X509_dup(other.cert_) : nullptr;
}

Certificate& Certificate::operator=(const Certificate& other) {
    if (this != &other) {
        if (cert_) X509_free(cert_);
        cert_ = other.cert_ ? X509_dup(other.cert_) : nullptr;
    }
    return *this;
}

Certificate::Certificate(Certificate&& other) noexcept {
    cert_ = other.cert_;
    other.cert_ = nullptr;
}

/*
Certificate& Certificate::operator=(Certificate&& other) noexcept {
    if (this != &other) {
        if (cert_) X509_free(cert_);
        cert_ = other.cert_;
        other.cert_ = nullptr;
    }
    return *this;
}
*/

bool Certificate::load_pem_file(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;

    X509* c = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!c) return false;

    if (cert_) X509_free(cert_);
    cert_ = c;
    return true;
}

bool Certificate::save_pem_file(const std::string& path) const {
    if (!cert_) return false;
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = PEM_write_X509(f, cert_);
    fclose(f);
    return ok;
}

std::string Certificate::subject() const {
    if (!cert_) return {};
    char buf[512];
    X509_NAME_oneline(X509_get_subject_name(cert_), buf, sizeof(buf));
    return buf;
}

std::string Certificate::issuer() const {
    if (!cert_) return {};
    char buf[512];
    X509_NAME_oneline(X509_get_issuer_name(cert_), buf, sizeof(buf));
    return buf;
}

time_t Certificate::not_before() const {
    if (!cert_) return 0;
    return ASN1_TIME_get(X509_get0_notBefore(cert_));
}

time_t Certificate::not_after() const {
    if (!cert_) return 0;
    return ASN1_TIME_get(X509_get0_notAfter(cert_));
}

bool Certificate::is_valid_now() const {
    time_t now = std::time(nullptr);
    return now >= not_before() && now <= not_after();
}

bool Certificate::fingerprint_sha256(std::vector<uint8_t>& out) const {
    if (!cert_) return false;
    unsigned int len = 0;
    out.resize(EVP_MAX_MD_SIZE);
    if (!X509_digest(cert_, EVP_sha256(), out.data(), &len))
        return false;
    out.resize(len);
    return true;
}

EVP_PKEY* Certificate::extract_public_key() const {
    if (!cert_) return nullptr;
    return X509_get_pubkey(cert_); // caller owns
}


//////////////////////////////


time_t Certificate::ASN1_TIME_get(const ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        t.tm_year = (str[i++] - '0') * 10;
        t.tm_year += (str[i++] - '0');
        if (t.tm_year < 70)
            t.tm_year += 100;
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        t.tm_year = (str[i++] - '0') * 1000;
        t.tm_year+= (str[i++] - '0') * 100;
        t.tm_year+= (str[i++] - '0') * 10;
        t.tm_year+= (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon  = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday+= (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour+= (str[i++] - '0');
    t.tm_min  = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec  = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');

    /* Note: we did not adjust the time based on time zone information */
    return mktime(&t);
}



} }