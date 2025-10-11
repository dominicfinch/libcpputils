
#include "dh.h"
#include <sstream>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace iar { namespace utils {

    DiffieHellman::DiffieHellman() {}

    DiffieHellman::~DiffieHellman() {
        clear_keypair();
    }

    void DiffieHellman::clear_keypair()
    {
        if(params != nullptr) {
            EVP_PKEY_free(params);
            params = nullptr;
        }

        if(keypair != nullptr) {
            EVP_PKEY_free(keypair);
            keypair = nullptr;
        }

        if(peerkey != nullptr) {
            EVP_PKEY_free(peerkey);
            peerkey = nullptr;
        }
    }

    bool DiffieHellman::generate_parameters(unsigned int prime_len)
    {
        auto success = false;
        clear_keypair();

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
        if(ctx != nullptr) {
            if (EVP_PKEY_paramgen_init(ctx) > 0 && EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, prime_len) > 0)
            {
                if (EVP_PKEY_paramgen(ctx, &params) > 0) {
                    //keypair = params;
                    success = true;
                }
            }
        }
        EVP_PKEY_CTX_free(ctx);
        return success;
    }

    bool DiffieHellman::generate_keypair()
    {
        bool success = false;
        if(params != nullptr)
        {
            EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, nullptr);
            if(kctx != nullptr)
            {
                if (EVP_PKEY_keygen_init(kctx) > 0) {
                    success = EVP_PKEY_keygen(kctx, &keypair) > 0;
                }
                EVP_PKEY_CTX_free(kctx);
            }
        }
        return success;
    }

    bool DiffieHellman::get_parameters(std::vector<uint8_t>& out)
    {
        auto success = false;
        if(params != nullptr) {
            BIO* mem = BIO_new(BIO_s_mem());
            if(mem != nullptr) {
                if(i2d_KeyParams_bio(mem, params)) {
                    BUF_MEM* bptr;
                    BIO_get_mem_ptr(mem, &bptr);
                    if (bptr != nullptr || bptr->length > 0) {
                        out.assign(bptr->data, bptr->data + bptr->length);
                        success = true;
                    }
                }
            }
            BIO_free(mem);
        }
        return success;
    }
    
    bool DiffieHellman::set_parameters(const std::vector<uint8_t>& in)
    {
        auto success = false;
        if(params != nullptr) {
            EVP_PKEY_free(params);
            params = nullptr;
        }

        const uint8_t* ptr = in.data();
        params = d2i_KeyParams(EVP_PKEY_DH, nullptr, &ptr, in.size());
        if(params != nullptr) {
            success = true;
        }
        return success;
    }

    bool DiffieHellman::public_key(std::vector<uint8_t>& key)
    {
        auto success = false;
        if(keypair != nullptr) {
            unsigned char* buffer = nullptr;
            int len = i2d_PUBKEY(keypair, &buffer);
            if(len > 0) {
                key.clear();
                key.assign(buffer, buffer + len);
                OPENSSL_free(buffer);
                success = true;
            }
        }
        return success;
    }

    bool DiffieHellman::public_key(std::string& key)
    {
        auto success = false;

        if(keypair != nullptr) {
            BIO* mem = BIO_new(BIO_s_mem());
            if(mem != nullptr) {
                if(PEM_write_bio_PUBKEY(mem, keypair)) {
                    char* data = nullptr;
                    long len = BIO_get_mem_data(mem, &data);
                    if (len > 0 && data) {
                        key.clear();
                        key.assign(data, len);
                        success = true;
                    }
                }
            }
            BIO_free(mem);
        }

        return success;
    }

    bool DiffieHellman::set_peer_public_key(const std::vector<uint8_t>& peer_pubkey)
    {
        const unsigned char* p = peer_pubkey.data();
        peerkey = d2i_PUBKEY(nullptr, &p, peer_pubkey.size());
        return peerkey != nullptr;
    }

    bool DiffieHellman::compute_shared_secret(std::vector<uint8_t>& shared_secret)
    {
        auto success = false;

        if(keypair != nullptr && peerkey != nullptr)
        {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair, nullptr);
            if(ctx != nullptr) {
                if (EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, peerkey) > 0)
                {
                    size_t secret_len = 0;
                    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) > 0) {
                        shared_secret.clear();
                        shared_secret.resize(secret_len);
                        if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) > 0) {
                            shared_secret.resize(secret_len);
                            success = true;
                        }
                    }
                }
            }
            EVP_PKEY_CTX_free(ctx);
        }
        return success;
    }

}}