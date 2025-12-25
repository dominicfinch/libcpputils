/*
 © Copyright 2025 Dominic Finch
*/

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sstream>
#include <iostream>

#include "aes.h"
#include "base64.h"
#include "hex.h"
#include "file.h"
#include "macros.h"
#include "string_helpers.h"
#include "crypto_common.h"

namespace iar {
    namespace utils {

        AES::AES() {

        }

        AES::~AES() {
            clear_key();
        }

        void AES::clear_key() {
            std::fill(_master_key.begin(), _master_key.end(), 0);
            //std::fill(_key.begin(), _key.end(), 0);
            std::fill(_iv.begin(), _iv.end(), 0);
            std::fill(_salt.begin(), _salt.end(), 0);

            _master_key.clear();
            //_key.clear();
            _iv.clear();
            _salt.clear();
        }

        bool AES::generate_key(unsigned int keysize) {
            if((keysize == S_AES_KEY_SIZE) || (keysize == M_AES_KEY_SIZE) || (keysize == L_AES_KEY_SIZE))
            {
                auto ivlen = 0;
                if(_mode == AESMode::GCM)
                    ivlen = 12;
                else if(_mode == AESMode::CFB || _mode == AESMode::CBC)
                    ivlen = 16;
                
                _master_key.resize(keysize / 8);
                _iv.resize(ivlen);
                _salt.resize(SALT_LEN);

                if (RAND_bytes(_master_key.data(), keysize / 8) != 1) return false;
                if (RAND_bytes(_iv.data(), ivlen) != 1) return false;
                if (RAND_bytes(_salt.data(), SALT_LEN) != 1) return false;

                return true;
            }
            return false;
        }

        std::string AES::hex_encoded_key() {
            std::string encodedKey = utils::Hex::encode(_master_key);
            return encodedKey;
        }
        
        std::string AES::hex_encoded_salt() {
            std::string encodedSalt = utils::Hex::encode(_salt);
            return encodedSalt;
        }

        std::string AES::hex_encoded_iv() {
            std::string encodedIV = utils::Hex::encode(_iv);
            return encodedIV;
        }
        
        bool AES::import_key(const std::string& fpath)
        {
            if (file_exists(fpath)) {
                std::string content;
                if(utils::read_file_contents(fpath, content)) {
                    auto splits = utils::split(content, "\n");
                    for(auto split : splits)
                    {
                        auto line_split = utils::split(split, "=");

                        utils::ltrim(line_split[0]);
                        if(utils::toLower(line_split[0]) == "salt") {
                            _salt = utils::Hex::decode(line_split[1]);
                        } else if(utils::toLower(line_split[0]) == "key") {
                            _master_key = utils::Hex::decode(line_split[1]);
                        } else if(utils::toLower(line_split[0]) == "iv") {
                            _iv = utils::Hex::decode(line_split[1]);
                        }
                    }
                    return true;
                }
            }
            return false;
        }

        bool AES::export_key(const std::string& fpath) 
        {
            std::stringstream ss;
            ss << "salt=" << hex_encoded_salt() << "\n";
            ss << "key=" << hex_encoded_key() << "\n";
            ss << "iv=" << hex_encoded_iv() << "\n";
            return utils::write_file_contents(fpath, ss.str());
        }

        // ---------------- Low-level API ----------------
        bool AES::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& iv, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>* out_tag, std::vector<uint8_t>& session_key)
        {
            ciphertext.clear();
            auto ivlen = 0;
            if(_mode == AESMode::GCM)
                ivlen = 12;
            else if(_mode == AESMode::CFB || _mode == AESMode::CBC)
                ivlen = 16;

            if (salt.size() != SALT_LEN || iv.size() != ivlen)
                return false;

            // --- Derive per-message session key ---
            session_key.resize(_master_key.size());
            if (hkdf_sha256(
                    salt,
                    _master_key,
                    {'A','E','S','-','S','E','S','S'},
                    session_key,
                    session_key.size()) <= 0)
                return false;

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            bool success = false;
            try {
                const EVP_CIPHER* cipher = get_cipher();
                const int block_size = EVP_CIPHER_block_size(cipher);

                if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("EncryptInit failed");

                // GCM only
                if (_mode == AESMode::GCM) {
                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                            (int)iv.size(), nullptr) != 1)
                        throw std::runtime_error("Set IV length failed");
                }

                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                    session_key.data(), iv.data()) != 1)
                    throw std::runtime_error("EncryptInit key/iv failed");

                // Allocate enough room for padding (CBC/ECB)
                if(_mode == AESMode::CBC || _mode == AESMode::ECB)
                    ciphertext.resize(plaintext.size() + block_size);
                else
                    ciphertext.resize(plaintext.size());

                int outlen1 = 0;
                if (!plaintext.empty()) {
                    if (EVP_EncryptUpdate(ctx,
                                        ciphertext.data(),
                                        &outlen1,
                                        plaintext.data(),
                                        plaintext.size()) != 1)
                        throw std::runtime_error("EncryptUpdate failed");
                }

                int outlen2 = 0;
                if (EVP_EncryptFinal_ex(ctx,
                                        ciphertext.data() + outlen1,
                                        &outlen2) != 1)
                    throw std::runtime_error("EncryptFinal failed");

                ciphertext.resize(outlen1 + outlen2);

                // GCM tag only
                if (_mode == AESMode::GCM && out_tag) {
                    out_tag->resize(16);
                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_tag->data()) != 1)
                        throw std::runtime_error("Get GCM tag failed");
                }

                success = true;
            }
            catch (...) {
                ciphertext.clear();
                session_key.clear();
                if (out_tag) out_tag->clear();
            }

            EVP_CIPHER_CTX_free(ctx);
            return success;
        }

        bool AES::decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& iv, const std::vector<uint8_t>* tag, std::vector<uint8_t>& plaintext, std::vector<uint8_t>& session_key)
        {
            plaintext.clear();
            auto ivlen = 0;
            if(_mode == AESMode::GCM)
                ivlen = 12;
            else if(_mode == AESMode::CFB || _mode == AESMode::CBC)
                ivlen = 16;
            
            if (salt.size() != SALT_LEN || iv.size() != ivlen)
                return false;

            // --- Re-derive same session key ---
            session_key.resize(_master_key.size());
            if (hkdf_sha256(
                    salt,
                    _master_key,
                    {'A','E','S','-','S','E','S','S'},
                    session_key,
                    session_key.size()) <= 0)
                return false;

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return false;

            bool success = false;
            try {
                const EVP_CIPHER* cipher = get_cipher();
                const int block_size = EVP_CIPHER_block_size(cipher);

                if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("DecryptInit failed");

                if (_mode == AESMode::GCM) {
                    if (EVP_CIPHER_CTX_ctrl(ctx,
                                            EVP_CTRL_GCM_SET_IVLEN,
                                            (int)iv.size(),
                                            nullptr) != 1)
                        throw std::runtime_error("Set IV length failed");
                }

                if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                    session_key.data(), iv.data()) != 1)
                    throw std::runtime_error("DecryptInit key/iv failed");

                // GCM tag must be set BEFORE final
                if (_mode == AESMode::GCM && tag) {
                    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag->data())) != 1)
                        throw std::runtime_error("Set GCM tag failed");
                }

                plaintext.resize(ciphertext.size() + block_size);

                int outlen1 = 0;
                if (!ciphertext.empty()) {
                    if (EVP_DecryptUpdate(ctx,
                                        plaintext.data(),
                                        &outlen1,
                                        ciphertext.data(),
                                        ciphertext.size()) != 1)
                        throw std::runtime_error("DecryptUpdate failed");
                }

                int outlen2 = 0;
                if (EVP_DecryptFinal_ex(ctx,
                                        plaintext.data() + outlen1,
                                        &outlen2) != 1)
                    throw std::runtime_error("DecryptFinal failed");

                plaintext.resize(outlen1 + outlen2);
                success = true;
            }
            catch (...) {
                plaintext.clear();
                session_key.clear();
            }

            EVP_CIPHER_CTX_free(ctx);
            return success;
        }

        // ---------------- High-level API ----------------
        bool AES::encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& output)
        {
            auto ivlen = 0;
            if(_mode == AESMode::GCM)
                ivlen = 12;
            else if(_mode == AESMode::CFB || _mode == AESMode::CBC)
                ivlen = 16;
            
            std::vector<uint8_t> salt(SALT_LEN);
            std::vector<uint8_t> iv(ivlen);
            if (RAND_bytes(salt.data(), SALT_LEN) != 1) return false;
            if (RAND_bytes(iv.data(), ivlen) != 1) return false;

            std::vector<uint8_t> session_key;
            std::vector<uint8_t> ciphertext;
            std::vector<uint8_t> tag;

            if (!encrypt(plaintext, salt, iv, ciphertext, (_mode == AESMode::GCM ? &tag : nullptr), session_key))
                return false;

            output.reserve(SALT_LEN + ivlen + ciphertext.size() + tag.size());
            output.insert(output.end(), salt.begin(), salt.end());
            output.insert(output.end(), iv.begin(), iv.end());
            output.insert(output.end(), ciphertext.begin(), ciphertext.end());
            if (_mode == AESMode::GCM) output.insert(output.end(), tag.begin(), tag.end());

            return true;
        }

        bool AES::decrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& plaintext)
        {
            plaintext.clear();
            auto ivlen = 0;
            if(_mode == AESMode::GCM)
                ivlen = 12;
            else if(_mode == AESMode::CFB || _mode == AESMode::CBC)
                ivlen = 16;
            
            size_t min_len = SALT_LEN + ivlen;
            if (_mode == AESMode::GCM) min_len += 16;
            if (input.size() < min_len) return false;

            const uint8_t* ptr = input.data();
            std::vector<uint8_t> salt(ptr, ptr + SALT_LEN); ptr += SALT_LEN;
            std::vector<uint8_t> iv(ptr, ptr + ivlen); ptr += ivlen;

            size_t remaining = input.size() - SALT_LEN - ivlen;
            std::vector<uint8_t> tag;
            if (_mode == AESMode::GCM) {
                if (remaining < 16) return false;
                tag.assign(ptr + remaining - 16, ptr + remaining);
                remaining -= 16;
            }

            std::vector<uint8_t> ciphertext(ptr, ptr + remaining);
            std::vector<uint8_t> session_key;

            return decrypt(ciphertext, salt, iv, (_mode == AESMode::GCM ? &tag : nullptr), plaintext, session_key);
        }

        bool AES::encrypt(const std::string& input, std::string& output)
        {
            std::vector<uint8_t> plaintext(input.begin(), input.end());
            std::vector<uint8_t> encrypted;

            if (!encrypt(plaintext, encrypted))
                return false;

            std::string ciphertext_raw(encrypted.begin(), encrypted.end());
            return Base64::encode(ciphertext_raw, output);
        }

        bool AES::decrypt(const std::string& input, std::string& output)
        {
            std::string decoded_ciphertext;
            if (!Base64::decode(input, decoded_ciphertext))
                return false;

            std::vector<uint8_t> ciphertext(decoded_ciphertext.begin(), decoded_ciphertext.end());
            std::vector<uint8_t> decrypted;
            if (!decrypt(ciphertext, decrypted))
                return false;

            output.assign(decrypted.begin(), decrypted.end());
            return true;
        }

        /*
        bool AES::encrypt_file(const std::string& input_path, const std::string& output_path, const std::string& tag_path)
        {
            std::vector<uint8_t> iv(16);
            RAND_bytes(iv.data(), iv.size());

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
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
                    throw std::runtime_error("Set GCM IV length failed");

                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, _key.data(), iv.data()) != 1)
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
            if (_key.empty()) return false;

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
        */
        
        const EVP_CIPHER* AES::get_cipher() const {
            size_t key_len = _master_key.size();
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