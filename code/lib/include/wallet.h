#pragma once

#include <openssl/evp.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace iar { namespace utils {

    class CryptoWallet {
        public:
            CryptoWallet();
            CryptoWallet(const CryptoWallet& other);    // Copy constructor
            CryptoWallet(CryptoWallet&& other) noexcept;    // Move constructor
            ~CryptoWallet();

            CryptoWallet& operator=(CryptoWallet other) {   // Copy assignment
                std::swap(key, other.key);
                return *this;
            }

            CryptoWallet& operator=(CryptoWallet&& other) noexcept {    // Move assignment
                if (this != &other) {
                    clear_wallet_key();       // Free current key if any
                    key = other.key;          // Take ownership
                    other.key = nullptr;      // Nullify source
                }
                return *this;
            }

            bool operator==(const CryptoWallet& other) const {
                if (key == nullptr || other.key == nullptr) {
                    return key == other.key;  // both nullptr or one is nullptr
                }

            #if OPENSSL_VERSION_NUMBER >= 0x30000000L
                return EVP_PKEY_eq(key, other.key) == 1;
            #else
                return EVP_PKEY_cmp(key, other.key) == 1;
            #endif
            }


            bool operator!=(const CryptoWallet& other) const {
                return !(*this == other);
            }

            bool generate_wallet_key(const std::string& curve_name = "prime256v1");
            void clear_wallet_key();

            bool public_key(std::vector<uint8_t>& key);
            bool private_key(std::vector<uint8_t>& key);

            bool public_key(std::string& hex_key);
            bool private_key(std::string& hex_key);

            bool wallet_address(std::vector<uint8_t>& address);
            bool wallet_address(std::string& address);

            bool import_key(const std::string& privkey, const std::string& curve_name = "prime256v1");

            bool encrypt(const std::string& plaintext, std::string& ciphertext, std::string& tag, const std::vector<uint8_t>& peer_pubkey, std::vector<uint8_t>& iv, const std::string& curve_name = "prime256v1");
            bool decrypt(const std::string& ciphertext, std::string& plaintext, const std::string& tag, const std::vector<uint8_t>& peer_pubkey, const std::vector<uint8_t>& iv, const std::string& curve_name = "prime256v1");

            bool encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& tag, const std::vector<uint8_t>& peer_pubkey, std::vector<uint8_t>& iv, const std::string& curve_name = "prime256v1");
            bool decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& tag, const std::vector<uint8_t>& peer_pubkey, const std::vector<uint8_t>& iv, const std::string& curve_name = "prime256v1");

            bool sign(const std::vector<uint8_t>& message, std::vector<uint8_t>& signature, const std::string& curve_name = "prime256v1");
            bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, const std::string& curve_name = "prime256v1");

            bool sign(const std::string& message, std::string& signature, const std::string& curve_name = "prime256v1");
            bool verify(const std::string& message, const std::string& signature, const std::string& curve_name = "prime256v1");

        private:
            EVP_PKEY * key = nullptr;
            std::vector<std::string> supported_curve_groups = {
                "prime256v1",
                "secp384r1",
                "secp521r1"
            };

            const std::unordered_map<std::string, int> supported_curve_lengths = {
                {"prime256v1", 64},
                {"secp384r1", 96},
                {"secp521r1", 132}
            };
            
            int expected_hex_length_for_curve(const std::string& curve_name);
            bool is_valid_private_key_length(const std::string& privkey_hex, const std::string& curve_name);
            bool is_valid_curve(const std::string& curve);
            bool hkdf_sha256(const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& info, std::vector<uint8_t>& okm, size_t length);
    };

}}