
#include "wallet.h"
#include "base58.h"
#include "hex.h"

#include <openssl/core_names.h>
//#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/params.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
//#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <iostream>

namespace iar { namespace utils {

    CryptoWallet::CryptoWallet() {

    }

    CryptoWallet::CryptoWallet(const CryptoWallet& other) {
        key = nullptr;

        if (other.key != nullptr) {
            // Extract group name
            char group_name[80];
            size_t group_len = 0;
            if (EVP_PKEY_get_utf8_string_param(other.key, "group", group_name, sizeof(group_name), &group_len) != 1) {
                throw std::runtime_error("Failed to get curve group from source key");
            }

            // Extract private key bytes
            size_t priv_len = 0;
            if (EVP_PKEY_get_octet_string_param(other.key, "priv", nullptr, 0, &priv_len) != 1) {
                throw std::runtime_error("Failed to get private key length from source key");
            }

            std::vector<uint8_t> privkey(priv_len);
            if (EVP_PKEY_get_octet_string_param(other.key, "priv", privkey.data(), priv_len, nullptr) != 1) {
                throw std::runtime_error("Failed to get private key from source key");
            }

            // Reconstruct key
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
            if (!ctx) {
                throw std::runtime_error("Failed to create EVP_PKEY_CTX");
            }

            if (EVP_PKEY_fromdata_init(ctx) != 1) {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("Failed to init fromdata");
            }

            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("group", group_name, 0),
                OSSL_PARAM_construct_octet_string("priv", privkey.data(), privkey.size()),
                OSSL_PARAM_construct_end()
            };

            if (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) != 1) {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("Failed to reconstruct EVP_PKEY from parameters");
            }

            EVP_PKEY_CTX_free(ctx);
        }
    }

    CryptoWallet::CryptoWallet(CryptoWallet&& other) noexcept {
        key = other.key;
        other.key = nullptr;
    }

    CryptoWallet::~CryptoWallet() {
        clear_wallet_key();
    }

    bool CryptoWallet::generate_wallet_key(const std::string& curve_name) {
        auto success = false;
        
        if(is_valid_curve(curve_name)) {
            clear_wallet_key();

            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("group", const_cast<char*>(curve_name.c_str()), 0),
                OSSL_PARAM_construct_end()
            };

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
            if(ctx != nullptr) {
                if (EVP_PKEY_keygen_init(ctx) > 0) {
                    if (EVP_PKEY_CTX_set_params(ctx, params) > 0) {
                        if (EVP_PKEY_generate(ctx, &key) > 0) {
                            success = true;
                        }
                    }
                }
                EVP_PKEY_CTX_free(ctx);
            }
        } else {
            // Unsupported curve
            std::cout << "[ERROR]: Failed to resolve curve_name\n";
        }
        return success;
    }
    
    void CryptoWallet::clear_wallet_key() {
        if(key != nullptr) {
            EVP_PKEY_free(key);
            key = nullptr;
        }
    }

    bool CryptoWallet::public_key(std::vector<uint8_t>& pubkey) {
        if (!key) return false;

        size_t len = 0;
        // Get length of public key first
        if (EVP_PKEY_get_octet_string_param(key, "pub", nullptr, 0, &len) <= 0) {
            return false;
        }

        pubkey.resize(len);
        // Retrieve actual public key bytes
        if (EVP_PKEY_get_octet_string_param(key, "pub", pubkey.data(), len, &len) <= 0) {
            return false;
        }

        return true;
    }
    
    bool CryptoWallet::public_key(std::string& hex_key) {
        std::vector<uint8_t> pubkey;
        auto success = public_key(pubkey);
        hex_key = Hex::encode(pubkey);
        return success;
    }

    bool CryptoWallet::private_key(std::vector<uint8_t>& privkey) {
        if(key == nullptr) return false;
        int key_type = EVP_PKEY_base_id(key);
        size_t len = 0;

        if (key_type == EVP_PKEY_ED25519 || key_type == EVP_PKEY_ED448) {
            // ED keys support raw key extraction
            if (EVP_PKEY_get_raw_private_key(key, nullptr, &len) != 1) {
                return false;
            }
            privkey.resize(len);
            return EVP_PKEY_get_raw_private_key(key, privkey.data(), &len) == 1;
        } else {
            auto success = false;
            // For EC keys, export to PKCS#8 DER format and extract key from that
            // Using the encoder API (OpenSSL 3.0+)
            OSSL_ENCODER_CTX* ctx = OSSL_ENCODER_CTX_new_for_pkey(
                key,
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                "DER",
                nullptr,
                nullptr
            );

            if(ctx != nullptr) {
                BIO* mem = BIO_new(BIO_s_mem());
                if(mem != nullptr) {
                    if (OSSL_ENCODER_to_bio(ctx, mem) == 1) {
                        BUF_MEM* bptr = nullptr;
                        BIO_get_mem_ptr(mem, &bptr);
                        if (bptr && bptr->length > 0) {
                            privkey.assign(bptr->data, bptr->data + bptr->length);
                            success = true;
                        }
                    }
                    BIO_free(mem);
                }
                OSSL_ENCODER_CTX_free(ctx);
            }
            return success;
        }
    }

    bool CryptoWallet::private_key(std::string& hex_key) {
        std::vector<uint8_t> privkey;
        auto success = private_key(privkey);
        hex_key = Hex::encode(privkey);
        return success;
    }

    bool CryptoWallet::wallet_address(std::string& address) {
        std::vector<uint8_t> address_bytes;
        auto result = wallet_address(address_bytes);
        address = Base58::encode(address_bytes);
        return result;
    }

    bool CryptoWallet::wallet_address(std::vector<uint8_t>& address) {
        auto success = false;
        std::vector<uint8_t> pubkey;
        size_t len = 0;

        if(key != nullptr) {
            if (EVP_PKEY_get_octet_string_param(key, "pub", nullptr, 0, &len) > 0) {
                pubkey.resize(len);
                if (EVP_PKEY_get_octet_string_param(key, "pub", pubkey.data(), len, nullptr) > 0) {
                    uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
                    SHA256(pubkey.data(), pubkey.size(), sha256_hash);

                    uint8_t ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
                    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                    if(mdctx != nullptr) {
                        if(EVP_DigestInit_ex(mdctx, EVP_ripemd160(), nullptr) == 1) {
                            if(EVP_DigestUpdate(mdctx, sha256_hash, SHA256_DIGEST_LENGTH) == 1) {
                                unsigned int out_len = 0;
                                if(EVP_DigestFinal_ex(mdctx, ripemd160_hash, &out_len) == 1)
                                {
                                    address.clear();
                                    address.push_back(0x00); // Version byte (e.g., Bitcoin mainnet)
                                    address.insert(address.end(), ripemd160_hash, ripemd160_hash + RIPEMD160_DIGEST_LENGTH);

                                    // Checksum: double SHA256
                                    uint8_t checksum_input[21];
                                    memcpy(checksum_input, address.data(), 21);
                                    uint8_t hash1[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH];
                                    SHA256(checksum_input, 21, hash1);
                                    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

                                    address.insert(address.end(), hash2, hash2 + 4); // Add checksum
                                    success = true;
                                }
                            }
                        }
                        EVP_MD_CTX_free(mdctx);
                    }
                }
            }
        }
        return success;
    }

    bool CryptoWallet::import_key(const std::string& privkey, const std::string& curve_name) {
        auto success = false;
        if (privkey.empty()) return false;
        
        if(is_valid_curve(curve_name)) {
            clear_wallet_key();
            //if(is_valid_private_key_length(privkey, curve_name)) {
            std::vector<uint8_t> privkey_bytes = Hex::decode(privkey);

            BIO* bio = BIO_new_mem_buf(privkey_bytes.data(), static_cast<int>(privkey_bytes.size()));
            if(bio != nullptr) {
                 OSSL_DECODER_CTX* dctx = OSSL_DECODER_CTX_new_for_pkey(
                    &key,                         // Output key
                    "DER",                        // Input format
                    nullptr,                      // Output format (nullptr = native)
                    nullptr,                      // Key type (nullptr = auto-detect)
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                    nullptr,                      // libctx
                    nullptr                       // propquery
                );

                if (dctx != nullptr) {
                    if (OSSL_DECODER_from_bio(dctx, bio)) {
                        success = true;
                    }
                    OSSL_DECODER_CTX_free(dctx);
                }
                BIO_free(bio);
            }
            //}
        } else {
            // Unsupported curve
        }
        return success;
    }

    bool CryptoWallet::encrypt(const std::string& plaintext, std::string& ciphertext, std::string& tag, const std::vector<uint8_t>& peer_pubkey,
        std::vector<uint8_t>& iv, const std::string& curve_name)
    {
        std::vector<uint8_t> ct_vec;
        std::vector<uint8_t> pt_vec(plaintext.begin(), plaintext.end());
        std::vector<uint8_t> tag_vec;
        if (!encrypt(pt_vec, ct_vec, tag_vec, peer_pubkey, iv, curve_name)) return false;
        ciphertext = utils::Hex::encode(ct_vec);
        std::stringstream ss;
        ss << tag_vec.data();
        tag = ss.str();
        return true;
    }

    bool CryptoWallet::encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& tag, const std::vector<uint8_t>& peer_pubkey,
        std::vector<uint8_t>& iv, const std::string& curve_name)
    {
        if (!key) return false;
        if (!is_valid_curve(curve_name)) return false;

        ciphertext.clear();
        iv.clear();

        // 1. Import peer EC public key
        EVP_PKEY* peer_key = nullptr;
        EVP_PKEY_CTX* peer_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        if (!peer_ctx) return false;

        if (EVP_PKEY_fromdata_init(peer_ctx) <= 0) {
            EVP_PKEY_CTX_free(peer_ctx);
            return false;
        }

        OSSL_PARAM peer_params[] = {
            OSSL_PARAM_construct_utf8_string("group", const_cast<char*>(curve_name.c_str()), 0),
            OSSL_PARAM_construct_octet_string("pub", const_cast<uint8_t*>(peer_pubkey.data()), peer_pubkey.size()),
            OSSL_PARAM_construct_end()
        };

        if (EVP_PKEY_fromdata(peer_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY, peer_params) <= 0) {
            EVP_PKEY_CTX_free(peer_ctx);
            return false;
        }
        EVP_PKEY_CTX_free(peer_ctx);
        
        // 2. Derive shared secret
        EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!derive_ctx ||
            EVP_PKEY_derive_init(derive_ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(derive_ctx, peer_key) <= 0) {
            EVP_PKEY_free(peer_key);
            EVP_PKEY_CTX_free(derive_ctx);
            return false;
        }

        size_t secret_len = 0;
        if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0) {
            EVP_PKEY_free(peer_key);
            EVP_PKEY_CTX_free(derive_ctx);
            return false;
        }

        std::vector<uint8_t> shared_secret(secret_len);
        if (EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0) {
            EVP_PKEY_free(peer_key);
            EVP_PKEY_CTX_free(derive_ctx);
            return false;
        }

        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(derive_ctx);
        
        // 3. Derive AES key using HKDF-SHA256
        std::vector<uint8_t> aes_key(32);
        std::vector<uint8_t> salt = { 0x00 };
        std::vector<uint8_t> info = { 0x01 };

        if (!hkdf_sha256(shared_secret, salt, info, aes_key, 32)) {
            return false;
        }

        // 4. AES-256-GCM encryption
        constexpr size_t GCM_IV_LEN = 12;
        constexpr size_t GCM_TAG_LEN = 16;
        iv.resize(GCM_IV_LEN);
        if (RAND_bytes(iv.data(), GCM_IV_LEN) != 1) return false;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        std::vector<uint8_t> ct_buf(plaintext.size() + GCM_TAG_LEN);
        int outlen = 0;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
            EVP_EncryptUpdate(ctx, ct_buf.data(), &outlen, plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        int tmplen = 0;
        if (EVP_EncryptFinal_ex(ctx, ct_buf.data() + outlen, &tmplen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outlen += tmplen;

        tag.resize(GCM_TAG_LEN);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        EVP_CIPHER_CTX_free(ctx);

        ct_buf.resize(outlen);
        ct_buf.insert(ct_buf.end(), tag.data(), tag.data() + GCM_TAG_LEN);
        ciphertext = std::move(ct_buf);
        return true;
    }

    bool CryptoWallet::decrypt(const std::string& ciphertext, std::string& plaintext, const std::string& tag, const std::vector<uint8_t>& peer_pubkey, const std::vector<uint8_t>& iv, const std::string& curve_name)
    {
        std::vector<uint8_t> ct_vec = Hex::decode(ciphertext);
        std::vector<uint8_t> pt_vec;
        std::vector<uint8_t> tag_vec(tag.begin(), tag.end());
        if (!decrypt(ct_vec, pt_vec, tag_vec, peer_pubkey, iv, curve_name)) return false;
        plaintext.assign(pt_vec.begin(), pt_vec.end());
        return true;
    }

    bool CryptoWallet::decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& tag, const std::vector<uint8_t>& peer_pubkey, const std::vector<uint8_t>& iv, const std::string& curve_name)
    {
        if (!key || ciphertext.size() < 16 || iv.size() != 12) return false;

        // Import peer key
        EVP_PKEY* peer_key = nullptr;
        EVP_PKEY_CTX* peer_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        if (!peer_ctx) return false;

        if (EVP_PKEY_fromdata_init(peer_ctx) <= 0) {
            EVP_PKEY_CTX_free(peer_ctx);
            return false;
        }

        OSSL_PARAM peer_params[] = {
            OSSL_PARAM_construct_utf8_string("group", const_cast<char*>(curve_name.c_str()), 0),
            OSSL_PARAM_construct_octet_string("pub", const_cast<uint8_t*>(peer_pubkey.data()), peer_pubkey.size()),
            OSSL_PARAM_construct_end()
        };

        if (EVP_PKEY_fromdata(peer_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY, peer_params) <= 0) {
            EVP_PKEY_CTX_free(peer_ctx);
            return false;
        }
        EVP_PKEY_CTX_free(peer_ctx);

        // Derive shared secret
        EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0 || EVP_PKEY_derive_set_peer(derive_ctx, peer_key) <= 0) {
            EVP_PKEY_free(peer_key);
            EVP_PKEY_CTX_free(derive_ctx);
            return false;
        }

        size_t secret_len = 0;
        if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0) {
            EVP_PKEY_free(peer_key);
            EVP_PKEY_CTX_free(derive_ctx);
            return false;
        }

        std::vector<uint8_t> shared_secret(secret_len);
        if (EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0) {
            EVP_PKEY_free(peer_key);
            EVP_PKEY_CTX_free(derive_ctx);
            return false;
        }

        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(derive_ctx);

        // Derive AES key
        std::vector<uint8_t> aes_key(32);
        std::vector<uint8_t> salt = { 0x00 };
        std::vector<uint8_t> info = { 0x01 };

        if (!hkdf_sha256(shared_secret, salt, info, aes_key, 32)) {
            return false;
        }

        // AES-GCM decryption
        constexpr size_t GCM_TAG_LEN = 16;
        const size_t ct_len = ciphertext.size() - GCM_TAG_LEN;
        const uint8_t* tag_ptr = ciphertext.data() + ct_len;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        plaintext.resize(ct_len);
        int outlen = 0;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
            EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(), ct_len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag_ptr) != 1 ||
            EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    bool CryptoWallet::sign(const std::vector<uint8_t>& message, std::vector<uint8_t>& signature, const std::string& curve_name)
    {
        if (!key) return false;

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) return false;

        if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, key) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }

        if (EVP_DigestSignUpdate(mdctx, message.data(), message.size()) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }

        size_t sig_len = 0;
        if (EVP_DigestSignFinal(mdctx, nullptr, &sig_len) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }

        signature.resize(sig_len);
        if (EVP_DigestSignFinal(mdctx, signature.data(), &sig_len) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }

        signature.resize(sig_len);
        EVP_MD_CTX_free(mdctx);
        return true;
    }

    bool CryptoWallet::sign(const std::string& message, std::string& signature, const std::string& curve_name)
    {
        std::vector<uint8_t> sig_bytes;
        std::vector<uint8_t> msg_bytes(message.begin(), message.end());
        if (!sign(msg_bytes, sig_bytes, curve_name)) return false;
        signature = Hex::encode(sig_bytes);
        return true;
    }

    bool CryptoWallet::verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, const std::string& curve_name)
    {
        if (!key) return false;

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) return false;

        if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, key) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }

        if (EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }

        int result = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
        EVP_MD_CTX_free(mdctx);

        return result == 1;
    }

    bool CryptoWallet::verify(const std::string& message, const std::string& signature, const std::string& curve_name)
    {
        std::vector<uint8_t> msg_bytes(message.begin(), message.end());
        std::vector<uint8_t> sig_bytes = Hex::decode(signature);
        return verify(msg_bytes, sig_bytes, curve_name);
    }

    /////////////////////
    // Private Methods //
    /////////////////////

    int CryptoWallet::expected_hex_length_for_curve(const std::string& curve_name) {
        auto it = supported_curve_lengths.find(curve_name);
        if (it != supported_curve_lengths.end()) {
            return it->second;
        }
        return -1; // Unknown curve
    }

    bool CryptoWallet::is_valid_private_key_length(const std::string& privkey_hex, const std::string& curve_name) {
        int expected_length = expected_hex_length_for_curve(curve_name);
        if (expected_length < 0) {
            throw std::invalid_argument("Unsupported curve: " + curve_name);
        }
        return privkey_hex.length() == static_cast<size_t>(expected_length);
    }

    bool CryptoWallet::is_valid_curve(const std::string& curve) {
        auto curve_it = std::find(supported_curve_groups.begin(), supported_curve_groups.end(), curve);
        return curve_it != supported_curve_groups.end();
    }

    bool CryptoWallet::hkdf_sha256(const std::vector<uint8_t>& ikm,
                 const std::vector<uint8_t>& salt,
                 const std::vector<uint8_t>& info,
                 std::vector<uint8_t>& okm, size_t length)
    {
        const size_t hash_len = 32;  // SHA-256 output size
        std::vector<uint8_t> prk(hash_len);

        // === Step 1: Extract PRK = HMAC(salt, ikm) ===
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (!mac) return false;

        EVP_MAC_CTX* mac_ctx = EVP_MAC_CTX_new(mac);
        if (!mac_ctx) {
            EVP_MAC_free(mac);
            return false;
        }

        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
            OSSL_PARAM_construct_end()
        };

        if (EVP_MAC_init(mac_ctx, salt.data(), salt.size(), params) <= 0 ||
            EVP_MAC_update(mac_ctx, ikm.data(), ikm.size()) <= 0 ||
            EVP_MAC_final(mac_ctx, prk.data(), nullptr, prk.size()) <= 0) {
            EVP_MAC_CTX_free(mac_ctx);
            EVP_MAC_free(mac);
            return false;
        }

        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);

        // === Step 2: Expand PRK with info to derive OKM ===
        size_t N = (length + hash_len - 1) / hash_len;
        if (N > 255) return false;

        okm.clear();
        okm.reserve(N * hash_len);

        std::vector<uint8_t> previous;
        for (uint8_t i = 1; i <= N; ++i) {
            std::vector<uint8_t> data;
            data.insert(data.end(), previous.begin(), previous.end());
            data.insert(data.end(), info.begin(), info.end());
            data.push_back(i);

            // Recreate MAC context for each iteration
            mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
            mac_ctx = EVP_MAC_CTX_new(mac);
            if (!mac_ctx) {
                EVP_MAC_free(mac);
                return false;
            }

            OSSL_PARAM params2[] = {
                OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
                OSSL_PARAM_construct_end()
            };

            std::vector<uint8_t> output(hash_len);
            if (EVP_MAC_init(mac_ctx, prk.data(), prk.size(), params2) <= 0 ||
                EVP_MAC_update(mac_ctx, data.data(), data.size()) <= 0 ||
                EVP_MAC_final(mac_ctx, output.data(), nullptr, output.size()) <= 0) {
                EVP_MAC_CTX_free(mac_ctx);
                EVP_MAC_free(mac);
                return false;
            }

            EVP_MAC_CTX_free(mac_ctx);
            EVP_MAC_free(mac);

            okm.insert(okm.end(), output.begin(), output.end());
            previous = std::move(output);
        }

        okm.resize(length);  // Truncate to exact desired length
        return true;
    }
}}