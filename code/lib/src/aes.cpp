
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sstream>

#include "aes.h"
#include "base64.h"
#include "hex.h"
#include "file.h"
#include "macros.h"
#include "string_helpers.h"

namespace iar {
    namespace utils {

        AES::AES() {

        }

        AES::~AES() {
            clear_key();
        }

        void AES::clear_key() {
            std::fill(_key.begin(), _key.end(), 0);
            std::fill(_iv.begin(), _iv.end(), 0);
            _key.clear();
            _iv.clear();
        }

        bool AES::generate_key(unsigned int keysize) {
            if((keysize == S_AES_KEY_SIZE) || (keysize == M_AES_KEY_SIZE) || (keysize == L_AES_KEY_SIZE))
            {
                _key.resize(keysize / 8);
                _iv.resize(16);
                auto key_allocate_success = RAND_bytes(_key.data(), keysize / 8) > 0;
                auto iv_allocate_success = RAND_bytes(_iv.data(), 16) > 0;
                return key_allocate_success && iv_allocate_success;
            }
            return false;
        }

        std::string AES::hex_encoded_key() {
            std::string encodedKey = utils::Hex::encode(_key);
            return encodedKey;
        }

        std::string AES::hex_encoded_iv() {
            std::string encodedIv = utils::Hex::encode(_iv);
            return encodedIv;
        }

        bool AES::import_key(const std::string& fpath) {
            bool success = false;
            if (file_exists(fpath)) {
                std::string content;
                if(utils::read_file_contents(fpath, content)) {
                    auto splits = utils::split(content, ":");

                    if(splits.size() == 2)
                    {
                        clear_key();
                        _key = utils::Hex::decode(splits.front());
                        _iv = utils::Hex::decode(splits.back());
                        success = true;
                    }
                }
            }
            return success;
        }

        bool AES::export_key(const std::string& fpath) {
            bool success = false;
            std::stringstream ss;
            ss << hex_encoded_key() << ":" << hex_encoded_iv();
            return utils::write_file_contents(fpath, ss.str());
        }

        bool AES::encrypt(const std::string& plaintext, std::string& ciphertext_base64, std::string& out_tag_base64) {
            std::vector<uint8_t> input(plaintext.begin(), plaintext.end());
            std::vector<uint8_t> encrypted;
            std::vector<uint8_t> tag;

            if (!encrypt(input, encrypted, &tag))
                return false;

            std::string ciphertext_raw(encrypted.begin(), encrypted.end());
            if (!Base64::encode(ciphertext_raw, ciphertext_base64))
                return false;

            if (_mode == AESMode::GCM) {
                std::string tag_raw(tag.begin(), tag.end());
                if (!Base64::encode(tag_raw, out_tag_base64))
                    return false;
            } else {
                out_tag_base64.clear(); // Not needed for ECB/CBC
            }

            return true;
        }

        bool AES::decrypt(const std::string& ciphertext_base64, std::string& plaintext, std::string& in_tag_base64) {
            std::string decoded_ciphertext;
            if (!Base64::decode(ciphertext_base64, decoded_ciphertext))
                return false;

            std::vector<uint8_t> ciphertext(decoded_ciphertext.begin(), decoded_ciphertext.end());
            std::vector<uint8_t> tag;

            if (_mode == AESMode::GCM) {
                std::string decoded_tag;
                if (!Base64::decode(in_tag_base64, decoded_tag) || decoded_tag.size() != 16)
                    return false;
                tag.assign(decoded_tag.begin(), decoded_tag.end());
            }

            std::vector<uint8_t> decrypted;
            if (!decrypt(ciphertext, decrypted, _mode == AESMode::GCM ? &tag : nullptr))
                return false;

            plaintext.assign(decrypted.begin(), decrypted.end());
            return true;
        }


        bool AES::encrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, std::vector<uint8_t>* out_tag) {
            output.clear();
            if (_key.empty()) return false;
            if (_mode != AESMode::ECB && _iv.empty()) return false;

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            bool success = false;
            int out_len1 = 0, out_len2 = 0;

            try {
                const EVP_CIPHER* cipher = get_cipher();

                if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("EncryptInit failed");

                if (_mode == AESMode::GCM) {
                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, _iv.size(), nullptr) != 1)
                        throw std::runtime_error("Set IV length failed");
                }

                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, _key.data(), _iv.empty() ? nullptr : _iv.data()) != 1)
                    throw std::runtime_error("EncryptInit key/iv failed");

                output.resize(input.size() + EVP_CIPHER_block_size(cipher));

                if (EVP_EncryptUpdate(ctx, output.data(), &out_len1, input.data(), input.size()) != 1)
                    throw std::runtime_error("EncryptUpdate failed");

                if (EVP_EncryptFinal_ex(ctx, output.data() + out_len1, &out_len2) != 1)
                    throw std::runtime_error("EncryptFinal failed");

                output.resize(out_len1 + out_len2);

                if (_mode == AESMode::GCM && out_tag) {
                    out_tag->resize(16);
                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_tag->data()) != 1)
                        throw std::runtime_error("Get GCM tag failed");
                }

                success = true;
            } catch (const std::exception& ex) {
                fprintf(stderr, "Encryption error: %s\n", ex.what());
                output.clear();
            }

            EVP_CIPHER_CTX_free(ctx);
            return success;
        }

        bool AES::decrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, std::vector<uint8_t>* in_tag) {
            output.clear();
            if (_key.empty()) return false;
            if (_mode != AESMode::ECB && _iv.empty()) return false;

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            bool success = false;
            int out_len1 = 0, out_len2 = 0;

            try {
                const EVP_CIPHER* cipher = get_cipher();

                if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("DecryptInit failed");

                if (_mode == AESMode::GCM) {
                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, _iv.size(), nullptr) != 1)
                        throw std::runtime_error("Set IV length failed");
                }

                if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, _key.data(), _iv.empty() ? nullptr : _iv.data()) != 1)
                    throw std::runtime_error("DecryptInit key/iv failed");

                if (_mode == AESMode::GCM) {
                    if (!in_tag || in_tag->size() != 16)
                        throw std::runtime_error("Missing or invalid GCM tag");

                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(in_tag->data())) != 1)
                        throw std::runtime_error("Set GCM tag failed");
                }

                output.resize(input.size() + EVP_CIPHER_block_size(cipher));

                if (EVP_DecryptUpdate(ctx, output.data(), &out_len1, input.data(), input.size()) != 1)
                    throw std::runtime_error("DecryptUpdate failed");

                if (EVP_DecryptFinal_ex(ctx, output.data() + out_len1, &out_len2) != 1)
                    throw std::runtime_error("DecryptFinal failed");

                output.resize(out_len1 + out_len2);
                success = true;
            } catch (const std::exception& ex) {
                fprintf(stderr, "Decryption error: %s\n", ex.what());
                output.clear();
            }

            EVP_CIPHER_CTX_free(ctx);
            return success;
        }


        bool AES::encrypt_file(const std::string& input_path, const std::string& output_path, const std::string& tag_path) {
            if (_key.empty() || _iv.empty()) return false;

            std::ifstream infile(input_path, std::ios::binary);
            std::ofstream outfile(output_path, std::ios::binary);
            if (!infile || !outfile) return false;

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            std::vector<uint8_t> tag;
            bool success = false;
            try {
                const EVP_CIPHER* cipher = get_cipher();

                if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("EncryptInit failed");

                if (_mode == AESMode::GCM &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, _iv.size(), nullptr) != 1)
                    throw std::runtime_error("Set GCM IV length failed");

                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, _key.data(), _iv.data()) != 1)
                    throw std::runtime_error("EncryptInit (key/iv) failed");

                std::vector<uint8_t> in_buf(AES_BUFFER_SIZE);
                std::vector<uint8_t> out_buf(AES_BUFFER_SIZE + EVP_CIPHER_block_size(cipher));

                int out_len = 0;

                while (infile.good()) {
                    infile.read(reinterpret_cast<char*>(in_buf.data()), in_buf.size());
                    std::streamsize read_bytes = infile.gcount();
                    if (read_bytes == 0) break;

                    if (EVP_EncryptUpdate(ctx, out_buf.data(), &out_len, in_buf.data(), read_bytes) != 1)
                        throw std::runtime_error("EncryptUpdate failed");

                    outfile.write(reinterpret_cast<char*>(out_buf.data()), out_len);
                }

                if (_mode != AESMode::GCM) {
                    if (EVP_EncryptFinal_ex(ctx, out_buf.data(), &out_len) != 1)
                        throw std::runtime_error("EncryptFinal failed");
                    outfile.write(reinterpret_cast<char*>(out_buf.data()), out_len);
                } else {
                    // No final block written for GCM
                    if (_mode == AESMode::GCM) {
                        if (EVP_EncryptFinal_ex(ctx, nullptr, &out_len) != 1)
                            throw std::runtime_error("EncryptFinal failed");

                        tag.resize(16);
                        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1)
                            throw std::runtime_error("Get GCM tag failed");

                        if (!tag_path.empty()) {
                            std::ofstream tag_file(tag_path, std::ios::binary);
                            tag_file.write(reinterpret_cast<const char*>(tag.data()), tag.size());
                        }
                    } else {
                        if (EVP_EncryptFinal_ex(ctx, out_buf.data(), &out_len) != 1)
                            throw std::runtime_error("EncryptFinal failed");
                        outfile.write(reinterpret_cast<char*>(out_buf.data()), out_len);
                    }

                    if (!tag_path.empty()) {
                        std::ofstream tag_file(tag_path, std::ios::binary);
                        tag_file.write(reinterpret_cast<const char*>(tag.data()), tag.size());
                    }
                }

                success = true;

            } catch (const std::exception& e) {
                fprintf(stderr, "File encryption failed: %s\n", e.what());
            }

            EVP_CIPHER_CTX_free(ctx);
            return success;
        }

        bool AES::decrypt_file(const std::string& input_path, const std::string& output_path, const std::string& tag_path) {
            if (_key.empty() || _iv.empty()) return false;

            std::ifstream infile(input_path, std::ios::binary);
            std::ofstream outfile(output_path, std::ios::binary);
            if (!infile || !outfile) return false;

            std::vector<uint8_t> tag;
            if (_mode == AESMode::GCM && !tag_path.empty()) {
                std::ifstream tag_file(tag_path, std::ios::binary);
                if (!tag_file) return false;

                tag.resize(16);
                tag_file.read(reinterpret_cast<char*>(tag.data()), tag.size());
            }

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            bool success = false;
            try {
                const EVP_CIPHER* cipher = get_cipher();

                if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("DecryptInit failed");

                if (_mode == AESMode::GCM &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, _iv.size(), nullptr) != 1)
                    throw std::runtime_error("Set GCM IV length failed");
                
                if (_mode == AESMode::GCM) {
                    if (tag.empty()) throw std::runtime_error("Missing GCM tag");
                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1)
                        throw std::runtime_error("Set GCM tag failed");
                }

                if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, _key.data(), _iv.data()) != 1)
                    throw std::runtime_error("DecryptInit (key/iv) failed");

                std::vector<uint8_t> in_buf(AES_BUFFER_SIZE);
                std::vector<uint8_t> out_buf(AES_BUFFER_SIZE + EVP_CIPHER_block_size(cipher));

                int out_len = 0;

                while (infile.good()) {
                    infile.read(reinterpret_cast<char*>(in_buf.data()), in_buf.size());
                    std::streamsize read_bytes = infile.gcount();
                    if (read_bytes == 0) break;

                    if (EVP_DecryptUpdate(ctx, out_buf.data(), &out_len, in_buf.data(), read_bytes) != 1)
                        throw std::runtime_error("DecryptUpdate failed");

                    outfile.write(reinterpret_cast<char*>(out_buf.data()), out_len);
                }

                if (EVP_DecryptFinal_ex(ctx, out_buf.data(), &out_len) != 1)
                    throw std::runtime_error("DecryptFinal failed");

                outfile.write(reinterpret_cast<char*>(out_buf.data()), out_len);
                success = true;

            } catch (const std::exception& e) {
                fprintf(stderr, "File decryption failed: %s\n", e.what());
            }

            EVP_CIPHER_CTX_free(ctx);
            return success;
        }

        bool AES::encrypt_stream(std::istream& in, std::ostream& out, std::ostream* tag_out) {
            // Read the full input from stream
            std::string input((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::vector<uint8_t> in_data(input.begin(), input.end());
            std::vector<uint8_t> out_data, tag;

            if (!encrypt(in_data, out_data, &tag))
                return false;

            // Write raw encrypted data to output stream
            out.write(reinterpret_cast<const char*>(out_data.data()), out_data.size());

            // If using GCM and a tag_out is provided, encode and write the tag
            if (_mode == AESMode::GCM && tag_out && !tag.empty()) {
                std::string tag_str(tag.begin(), tag.end());
                std::string encoded_tag;
                if (!Base64::encode(tag_str, encoded_tag))
                    return false;
                (*tag_out) << encoded_tag;
            }

            return true;
        }

        bool AES::decrypt_stream(std::istream& in, std::ostream& out, std::istream* tag_in) {
            std::vector<uint8_t> tag;

            // Handle GCM tag
            if (_mode == AESMode::GCM) {
                if (!tag_in) return false;

                // Read base64-encoded tag from stream
                std::string tag_base64((std::istreambuf_iterator<char>(*tag_in)), std::istreambuf_iterator<char>());
                std::string decoded_tag_str;
                if (!Base64::decode(tag_base64, decoded_tag_str) || decoded_tag_str.size() != 16)
                    return false;

                tag.assign(decoded_tag_str.begin(), decoded_tag_str.end());
            }

            // Read full encrypted input
            std::string input((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::vector<uint8_t> in_data(input.begin(), input.end());
            std::vector<uint8_t> out_data;

            if (!decrypt(in_data, out_data, (_mode == AESMode::GCM ? &tag : nullptr)))
                return false;

            // Write decrypted output
            out.write(reinterpret_cast<const char*>(out_data.data()), out_data.size());
            return true;
        }

        
        const EVP_CIPHER* AES::get_cipher() const {
            size_t key_len = _key.size();
            if (_mode == AESMode::ECB) {
                if (key_len == 16) return EVP_aes_128_ecb();
                if (key_len == 24) return EVP_aes_192_ecb();
                if (key_len == 32) return EVP_aes_256_ecb();
            } else if (_mode == AESMode::CBC) {
                if (key_len == 16) return EVP_aes_128_cbc();
                if (key_len == 24) return EVP_aes_192_cbc();
                if (key_len == 32) return EVP_aes_256_cbc();
            }
            else if (_mode == AESMode::CFB) {
                if (key_len == 16) return EVP_aes_128_cfb();
                if (key_len == 24) return EVP_aes_192_cfb();
                if (key_len == 32) return EVP_aes_256_cfb();
            }
            /*
            else if (_mode == AESMode::OFB) {
                if (key_len == 16) return EVP_aes_128_ofb();
                if (key_len == 24) return EVP_aes_192_ofb();
                if (key_len == 32) return EVP_aes_256_ofb();
            } else if (_mode == AESMode::CTR) {
                if (key_len == 16) return EVP_aes_128_ctr();
                if (key_len == 24) return EVP_aes_192_ctr();
                if (key_len == 32) return EVP_aes_256_ctr();
            }
                */
            else if (_mode == AESMode::GCM) {
                if (key_len == 16) return EVP_aes_128_gcm();
                if (key_len == 24) return EVP_aes_192_gcm();
                if (key_len == 32) return EVP_aes_256_gcm();
            }

            throw std::runtime_error("Unsupported mode or key size");
        }


    }
}