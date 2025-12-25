#include "crypto_common.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace iar { namespace utils {

bool hkdf_sha256(const std::vector<uint8_t>& salt,
                        const std::vector<uint8_t>& ikm,
                        const std::vector<uint8_t>& info,
                        std::vector<uint8_t>& okm, // out
                        size_t L)
{
    if (L == 0) return false;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return false;

    bool ok = false;
    unsigned char* outbuf = (unsigned char*)OPENSSL_malloc(L);
    if (!outbuf) { EVP_PKEY_CTX_free(pctx); return false; }

    if (EVP_PKEY_derive_init(pctx) > 0) {
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0) {
            // If salt is provided set1; otherwise don't set (HKDF spec treats empty salt as zeros)
            if (!salt.empty()) {
                if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size()) > 0) {
                    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size()) > 0) {
                        if (!info.empty()) {
                            if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size()) > 0) {
                                size_t outlen = L;
                                if (EVP_PKEY_derive(pctx, outbuf, &outlen) > 0) {
                                    if (outlen == L) {
                                        okm.assign(outbuf, outbuf + outlen);
                                        ok = true;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size()) > 0) {
                    if (!info.empty()) {
                        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size()) > 0) {
                            size_t outlen = L;
                            if (EVP_PKEY_derive(pctx, outbuf, &outlen) > 0) {
                                if (outlen == L) {
                                    okm.assign(outbuf, outbuf + outlen);
                                    ok = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    OPENSSL_cleanse(outbuf, L);
    OPENSSL_free(outbuf);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

} }