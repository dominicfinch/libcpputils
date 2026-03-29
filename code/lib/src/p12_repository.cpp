#include "p12_repository.h"
#include "certificate.h"

#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <sstream>

namespace cpp { namespace utils {

P12Repository::P12Repository()
    : private_key_(nullptr) {}

P12Repository::~P12Repository() {
    clear();
}

P12Repository::P12Repository(P12Repository&& other) noexcept {
    private_key_ = other.private_key_;
    certificates_ = std::move(other.certificates_);
    leaf_cert_ = std::move(other.leaf_cert_);
    other.private_key_ = nullptr;
}

P12Repository& P12Repository::operator=(P12Repository&& other) noexcept {
    if (this != &other) {
        clear();
        private_key_ = other.private_key_;
        certificates_ = std::move(other.certificates_);
        leaf_cert_ = std::move(other.leaf_cert_);
        other.private_key_ = nullptr;
    }
    return *this;
}

void P12Repository::clear() {
    if (private_key_) {
        EVP_PKEY_free(private_key_);
        private_key_ = nullptr;
    }
    certificates_.clear();
    leaf_cert_.reset();
}

bool P12Repository::load_from_file(const std::string& path, const std::string& password) {
    clear();

    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return false;

    PKCS12* p12 = d2i_PKCS12_fp(fp, nullptr);
    fclose(fp);
    if (!p12) return false;

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    bool ok = PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca);
    PKCS12_free(p12);
    if (!ok) return false;

    private_key_ = pkey;

    if (cert) {
        leaf_cert_ = std::make_shared<Certificate>(cert);
        certificates_.push_back(leaf_cert_);
        X509_free(cert);
    }

    if (ca) {
        for (int i = 0; i < sk_X509_num(ca); ++i) {
            X509* x = sk_X509_value(ca, i);
            certificates_.push_back(std::make_shared<Certificate>(x));
        }
        sk_X509_pop_free(ca, X509_free);
    }

    return true;
}

bool P12Repository::save_to_file(const std::string& path, const std::string& password) const {
    if (!leaf_cert_) return false;

    STACK_OF(X509)* ca = sk_X509_new_null();
    for (const auto& cert : certificates_) {
        if (cert != leaf_cert_) {
            sk_X509_push(ca, cert_to_x509(*cert));
        }
    }

    PKCS12* p12 = PKCS12_create(
        password.c_str(),
        "P12Repository",
        private_key_,
        cert_to_x509(*leaf_cert_),
        ca,
        0, 0, 0, 0, 0
    );

    sk_X509_pop_free(ca, X509_free);

    if (!p12) return false;

    FILE* fp = fopen(path.c_str(), "wb");
    if (!fp) {
        PKCS12_free(p12);
        return false;
    }

    bool ok = i2d_PKCS12_fp(fp, p12);
    fclose(fp);
    PKCS12_free(p12);
    return ok;
}

bool P12Repository::has_private_key() const {
    return private_key_ != nullptr;
}

EVP_PKEY* P12Repository::get_private_key() const {
    return private_key_;
}

bool P12Repository::set_private_key(EVP_PKEY* key) {
    if (!key) return false;
    if (private_key_) EVP_PKEY_free(private_key_);
    private_key_ = key;
    return true;
}

void P12Repository::remove_private_key() {
    if (private_key_) {
        EVP_PKEY_free(private_key_);
        private_key_ = nullptr;
    }
}

size_t P12Repository::certificate_count() const {
    return certificates_.size();
}

std::shared_ptr<Certificate> P12Repository::get_certificate(size_t index) const {
    if (index >= certificates_.size()) return nullptr;
    return certificates_[index];
}

std::vector<std::shared_ptr<Certificate>> P12Repository::get_all_certificates() const {
    return certificates_;
}

void P12Repository::add_certificate(const std::shared_ptr<Certificate>& cert) {
    certificates_.push_back(cert);
}

bool P12Repository::remove_certificate(size_t index) {
    if (index >= certificates_.size()) return false;
    certificates_.erase(certificates_.begin() + index);
    return true;
}

std::shared_ptr<Certificate> P12Repository::get_leaf_certificate() const {
    return leaf_cert_;
}

void P12Repository::set_leaf_certificate(const std::shared_ptr<Certificate>& cert) {
    leaf_cert_ = cert;
}

std::string P12Repository::describe() const {
    std::ostringstream oss;
    oss << "P12Repository\n";
    oss << "Private key: " << (private_key_ ? "yes" : "no") << "\n";
    oss << "Certificates: " << certificates_.size() << "\n";
    if (leaf_cert_) {
        oss << "Leaf CN: " << leaf_cert_->subject() << "\n";
    }
    return oss.str();
}

X509* P12Repository::cert_to_x509(const Certificate& cert) {
    return cert.raw();
}

} } // namespace cpp::utils
