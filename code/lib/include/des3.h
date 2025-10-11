
#pragma once

#include <vector>
#include <cstdint>
#include <openssl/evp.h>

namespace iar {
    namespace utils {

        enum class DES3Mode {
            CBC,
            ECB
        };

        class DES3 {
        public:
            DES3(DES3Mode mode = DES3Mode::CBC);
            ~DES3();

            void clear();

            bool generate_key();
            bool set_key(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv = {});
            
            const std::vector<uint8_t>& get_key() const { return key_; }
            const std::vector<uint8_t>& get_iv() const { return iv_; }

            bool encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext);
            bool decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext);

        private:
            const EVP_CIPHER* get_cipher() const;

            DES3Mode mode_;
            std::vector<uint8_t> key_;
            std::vector<uint8_t> iv_;
        };

    }
}