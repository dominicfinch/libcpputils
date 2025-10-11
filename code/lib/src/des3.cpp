
#include "des3.h"
#include <openssl/rand.h>
#include <stdexcept>

namespace iar { namespace utils {

    DES3::DES3(DES3Mode mode) : mode_(mode) {}

    DES3::~DES3() {
        clear();
    }

    void DES3::clear() {
        key_.clear();
        iv_.clear();
    }

    bool DES3::generate_key() {
        auto success = false;
        clear();

        key_.reserve(24);
        if (RAND_bytes(key_.data(), static_cast<int>(key_.size())) != 1) {
            throw std::runtime_error("OpenSSL RAND_bytes() failed to generate random data");
        }

        if(mode_ == DES3Mode::CBC) {
            iv_.reserve(8);
            if (RAND_bytes(iv_.data(), static_cast<int>(iv_.size())) != 1) {
                throw std::runtime_error("OpenSSL RAND_bytes() failed to generate random data");
            }
        }

        return success;
    }

    bool DES3::set_key(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
        if (key.size() != 24) return false;

        switch(mode_)
        {
            case DES3Mode::ECB:
                if (!iv.empty()) return false;
                break;
            case DES3Mode::CBC:
                if (iv.size() != 8) return false;
                iv_ = iv;
                break;
        }

        key_ = key;
        return true;
    }

    const EVP_CIPHER* DES3::get_cipher() const {
        switch (mode_) {
            case DES3Mode::CBC: return EVP_des_ede3_cbc();
            case DES3Mode::ECB: return EVP_des_ede3_ecb();
            // Add more as needed
            default: return nullptr;
        }
    }

    bool DES3::encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) {
        const EVP_CIPHER* cipher = get_cipher();
        if (!cipher || key_.size() != 24 || (EVP_CIPHER_iv_length(cipher) && iv_.size() != 8)) return false;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool success = false;
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key_.data(), iv_.empty() ? nullptr : iv_.data()) == 1) {
            std::vector<uint8_t> out(plaintext.size() + EVP_CIPHER_block_size(cipher));
            int out_len1 = 0, out_len2 = 0;

            if (EVP_EncryptUpdate(ctx, out.data(), &out_len1, plaintext.data(), plaintext.size()) == 1 &&
                EVP_EncryptFinal_ex(ctx, out.data() + out_len1, &out_len2) == 1) {
                out.resize(out_len1 + out_len2);
                ciphertext.swap(out);
                success = true;
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        return success;
    }

    bool DES3::decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext) {
        const EVP_CIPHER* cipher = get_cipher();
        if (!cipher || key_.size() != 24 || (EVP_CIPHER_iv_length(cipher) && iv_.size() != 8)) return false;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool success = false;
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key_.data(), iv_.empty() ? nullptr : iv_.data()) == 1) {
            std::vector<uint8_t> out(ciphertext.size());
            int out_len1 = 0, out_len2 = 0;

            if (EVP_DecryptUpdate(ctx, out.data(), &out_len1, ciphertext.data(), ciphertext.size()) == 1 &&
                EVP_DecryptFinal_ex(ctx, out.data() + out_len1, &out_len2) == 1) {
                out.resize(out_len1 + out_len2);
                plaintext.swap(out);
                success = true;
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        return success;
    }

}}