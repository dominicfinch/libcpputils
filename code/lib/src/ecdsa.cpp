#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include <vector>
#include <string>
#include <memory>
#include <fstream>
#include <iostream>

#include "ecdsa.h"

namespace iar {
namespace utils {

// --- Implementation ---

ECDSA::ECDSA() : pkey_(nullptr, EVP_PKEY_free) {
    OpenSSL_add_all_algorithms();
}

ECDSA::~ECDSA() {
    EVP_cleanup();
}

bool ECDSA::generate_keypair(int bits) {
    const char* curve_name = nullptr;
    if (bits == 384)
        curve_name = "P-384";
    else if (bits == 512 || bits == 521)
        curve_name = "P-521";
    else
        return false;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx)
        return false;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_generate(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    pkey_.reset(key);
    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool ECDSA::export_public_key(const std::string& path) {
    if (!pkey_) return false;
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    bool ok = PEM_write_PUBKEY(f, pkey_.get());
    fclose(f);
    return ok;
}

bool ECDSA::export_private_key(const std::string& path) {
    if (!pkey_) return false;
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    bool ok = PEM_write_PrivateKey(f, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    return ok;
}

bool ECDSA::import_private_key(const std::string& path) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return false;
    EVP_PKEY* tmp = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!tmp) return false;
    pkey_.reset(tmp);
    return true;
}

bool ECDSA::import_public_key(const std::string& path) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return false;
    EVP_PKEY* tmp = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!tmp) return false;
    pkey_.reset(tmp);
    return true;
}

bool ECDSA::sign(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature, const std::string& hash) {
    if (!pkey_) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    const EVP_MD* md = EVP_MD_fetch(nullptr, hash.c_str(), nullptr);
    if (!md) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    bool ok = false;
    if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey_.get()) > 0) {
        if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) > 0) {
            size_t siglen = 0;
            if (EVP_DigestSignFinal(ctx, nullptr, &siglen) <= 0) goto end;

            signature.resize(siglen);
            if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) <= 0) goto end;

            signature.resize(siglen);
            ok = true;
        }
    }

end:
    EVP_MD_free((EVP_MD*)md);
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool ECDSA::verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::string& hash) {
    if (!pkey_) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    const EVP_MD* md = EVP_MD_fetch(nullptr, hash.c_str(), nullptr);
    if (!md) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey_.get()) <= 0) goto end;

    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0) goto end;

    if (EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1)
        ok = true;

end:
    EVP_MD_free((EVP_MD*)md);
    EVP_MD_CTX_free(ctx);
    return ok;
}

std::string ECDSA::get_openssl_error() {
    char buf[256];
    unsigned long err = ERR_get_error();
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

} // namespace utils
} // namespace iar
