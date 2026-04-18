#include "crypto_common.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <cstring>

namespace cpp { namespace utils {

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

int openssl_password_cb(char* buf, int size, int, void* userdata)
{
    if (!userdata) return 0;

    auto* wrapper = static_cast<PasswordCallbackWrapper*>(userdata);
    std::string pass = wrapper->cb();

    if (pass.size() > static_cast<size_t>(size))
        return 0;

    memcpy(buf, pass.data(), pass.size());

    // Optional: cleanse memory (important!)
    OPENSSL_cleanse(pass.data(), pass.size());

    return static_cast<int>(pass.size());
}

bool match_hostname_pattern(const std::string& pattern, const std::string& hostname)
{
    // Exact match
    if (pattern == hostname)
        return true;

    // Wildcard: *.example.com
    if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.')
    {
        auto suffix = pattern.substr(1); // ".example.com"

        if (hostname.length() >= suffix.length())
        {
            auto pos = hostname.length() - suffix.length();
            if (hostname.compare(pos, suffix.length(), suffix) == 0)
            {
                // Ensure wildcard only matches one label
                // foo.example.com OK
                // bar.foo.example.com NOT OK
                auto first_dot = hostname.find('.');
                if (first_dot != std::string::npos &&
                    hostname.substr(first_dot) == suffix)
                    return true;
            }
        }
    }

    return false;
}

} }