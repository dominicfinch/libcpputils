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
            bool generate_key(unsigned int keysize = DEFAULT_AES_KEYSIZE);

            std::vector<uint8_t>& key() { return _key; }
            std::vector<uint8_t>& iv() { return _iv; }

            std::string hex_encoded_key();
            std::string hex_encoded_iv();

            bool import_key(const std::string& fpath);
            bool export_key(const std::string& fpath);

            bool encrypt(const std::string& input, std::string& output, std::string& out_tag);
            bool decrypt(const std::string& input, std::string& output, std::string& in_tag);

            bool encrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, std::vector<uint8_t>* out_tag = nullptr);
            bool decrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, std::vector<uint8_t>* in_tag = nullptr);

            bool encrypt_file(const std::string& input_path, const std::string& output_path, const std::string& tag_path);
            bool decrypt_file(const std::string& input_path, const std::string& output_path, const std::string& tag_path);

            bool encrypt_stream(std::istream& in, std::ostream& out, std::ostream* tag_out);
            bool decrypt_stream(std::istream& in, std::ostream& out, std::istream* tag_in);

            void set_mode(AESMode mode) { _mode = mode; }
            
        private:
            const size_t AES_BUFFER_SIZE = 1 << 12;         // 4096
            const EVP_CIPHER* get_cipher() const;

            std::vector<uint8_t> _key;
            std::vector<uint8_t> _iv;
            AESMode _mode = AESMode::GCM;
            std::mutex _lock_mutex;
        };

    }
}