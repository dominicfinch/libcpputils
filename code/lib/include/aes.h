/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <openssl/evp.h>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#define S_AES_KEY_SIZE      1 << 7                      //128
#define M_AES_KEY_SIZE      3 * S_AES_KEY_SIZE / 2      //192
#define L_AES_KEY_SIZE      1 << 8                      //256

#define DEFAULT_AES_KEYSIZE         L_AES_KEY_SIZE

namespace iar {
    namespace utils {

        enum class AESMode {
            ECB,
            CBC,
            CFB,
            //OFB,
            //CTR,
            GCM
        };

        class AES {
        public:
            AES();
            ~AES();

            void clear_key();
            void set_use_hkdf(bool state) { _raw_key_mode = state; }
            bool generate_key(unsigned int keysize = DEFAULT_AES_KEYSIZE);

            std::string hex_encoded_key();
            std::string hex_encoded_salt();
            std::string hex_encoded_iv();

            bool import_key(const std::string& fpath);
            bool export_key(const std::string& fpath);

            // Low-level API
            bool encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& iv, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>* out_tag, std::vector<uint8_t>& session_key);
            bool decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& iv, const std::vector<uint8_t>* tag, std::vector<uint8_t>& plaintext, std::vector<uint8_t>& session_key);

            // Higher-level API (embeds IV and salt into ciphertext)
            bool encrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
            bool decrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);

            bool encrypt(const std::string& input, std::string& output);
            bool decrypt(const std::string& input, std::string& output);

            bool encrypt_file(const std::string& in, const std::string& out);
            bool decrypt_file(const std::string& in, const std::string& out);

            //bool encrypt_stream(std::istream& in, std::ostream& out, std::ostream* tag_out);
            //bool decrypt_stream(std::istream& in, std::ostream& out, std::istream* tag_in);

            void set_mode(AESMode mode) { _mode = mode; }
            
        private:
            const size_t AES_BUFFER_SIZE = 1 << 12;         // 4096
            const EVP_CIPHER* get_cipher() const;

            std::vector<uint8_t> _master_key;
            std::vector<uint8_t> _salt;
            std::vector<uint8_t> _iv;

            const size_t SALT_LEN = 16;
            bool _raw_key_mode = false;
            AESMode _mode = AESMode::GCM;
            std::mutex _lock_mutex;
        };

    }
}