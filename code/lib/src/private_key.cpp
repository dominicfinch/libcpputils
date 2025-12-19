#include "private_key.h"
#include "certificate.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <cstdio>
#include <cstring>

namespace iar { namespace utils {

PrivateKey::PrivateKey() : pkey_(nullptr) {}

PrivateKey::PrivateKey(EVP_PKEY* pkey) : pkey_(pkey) {}

PrivateKey::~PrivateKey()
{
    if (pkey_)
        EVP_PKEY_free(pkey_);
}

PrivateKey::PrivateKey(PrivateKey&& other) noexcept : pkey_(other.pkey_)
{
    other.pkey_ = nullptr;
}

PrivateKey& PrivateKey::operator=(PrivateKey&& other) noexcept
{
    if (this != &other) {
        if (pkey_)
            EVP_PKEY_free(pkey_);
        pkey_ = other.pkey_;
        other.pkey_ = nullptr;
    }
    return *this;
}

int PrivateKey::password_cb(char* buf, int size, int, void* userdata)
{
    std::string* pass = static_cast<std::string*>(userdata);
    if (!pass) return 0;
    int len = static_cast<int>(pass->size());
    if (len > size) len = size;
    memcpy(buf, pass->data(), len);
    return len;
}

bool PrivateKey::load_pem(const std::string& path, const std::string& password)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;

    std::string pw = password;
    EVP_PKEY* key = PEM_read_PrivateKey(
        f, nullptr,
        password.empty() ? nullptr : password_cb,
        password.empty() ? nullptr : &pw
    );
    fclose(f);

    if (!key) return false;

    if (pkey_)
        EVP_PKEY_free(pkey_);
    pkey_ = key;
    return true;
}

bool PrivateKey::save_pem(const std::string& path, const std::string& password) const
{
    if (!pkey_) return false;

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;

    bool ok = false;
    if (password.empty()) {
        ok = PEM_write_PrivateKey(f, pkey_, nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        ok = PEM_write_PrivateKey(
            f, pkey_,
            EVP_aes_256_cbc(),
            reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
            static_cast<int>(password.size()),
            nullptr, nullptr
        );
    }
    fclose(f);
    return ok;
}

bool PrivateKey::load_der(const std::string& path)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;

    EVP_PKEY* key = d2i_PrivateKey_fp(f, nullptr);
    fclose(f);

    if (!key) return false;

    if (pkey_)
        EVP_PKEY_free(pkey_);
    pkey_ = key;
    return true;
}

bool PrivateKey::save_der(const std::string& path) const
{
    if (!pkey_) return false;

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;

    bool ok = i2d_PrivateKey_fp(f, pkey_);
    fclose(f);
    return ok;
}

bool PrivateKey::from_pem_string(const std::string& pem, const std::string& password)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return false;

    std::string pw = password;
    EVP_PKEY* key = PEM_read_bio_PrivateKey(
        bio, nullptr,
        password.empty() ? nullptr : password_cb,
        password.empty() ? nullptr : &pw
    );
    BIO_free(bio);

    if (!key) return false;

    if (pkey_)
        EVP_PKEY_free(pkey_);
    pkey_ = key;
    return true;
}

bool PrivateKey::to_pem_string(std::string& pem, const std::string& password) const
{
    if (!pkey_) return false;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;

    bool ok = false;
    if (password.empty()) {
        ok = PEM_write_bio_PrivateKey(bio, pkey_, nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        ok = PEM_write_bio_PrivateKey(
            bio, pkey_,
            EVP_aes_256_cbc(),
            reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
            static_cast<int>(password.size()),
            nullptr, nullptr
        );
    }

    if (!ok) {
        BIO_free(bio);
        return false;
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    pem.assign(data, len);
    BIO_free(bio);
    return true;
}

PrivateKey PrivateKey::generate_rsa(int bits)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx) return {};

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return PrivateKey(key);
}

PrivateKey PrivateKey::generate_ec(const std::string& curve)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return {};

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, OBJ_sn2nid(curve.c_str())) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return PrivateKey(key);
}

PrivateKey PrivateKey::generate_ed25519()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr);
    if (!ctx) return {};

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return PrivateKey(key);
}

bool PrivateKey::is_valid() const
{
    return pkey_ != nullptr;
}

int PrivateKey::key_type() const
{
    return pkey_ ? EVP_PKEY_id(pkey_) : EVP_PKEY_NONE;
}

int PrivateKey::key_bits() const
{
    return pkey_ ? EVP_PKEY_bits(pkey_) : 0;
}

std::string PrivateKey::key_type_name() const
{
    switch (key_type()) {
        case EVP_PKEY_RSA: return "RSA";
        case EVP_PKEY_EC: return "EC";
        case EVP_PKEY_ED25519: return "ED25519";
        default: return "UNKNOWN";
    }
}

EVP_PKEY* PrivateKey::get() const
{
    return pkey_;
}

bool PrivateKey::matches_certificate(const Certificate& cert) const
{
    if (!pkey_ || !cert.raw()) return false;
    EVP_PKEY* cert_key = X509_get_pubkey(cert.raw());
    if (!cert_key) return false;
    bool match = EVP_PKEY_cmp(pkey_, cert_key) == 1;
    EVP_PKEY_free(cert_key);
    return match;
}

} } // namespace iar::crypto
