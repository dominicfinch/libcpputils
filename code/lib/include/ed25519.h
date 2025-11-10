#pragma once

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>

namespace iar::utils {
static bool hkdf_sha256(const std::vector<uint8_t>& salt,
                        const std::vector<uint8_t>& ikm,
                        const std::vector<uint8_t>& info,
                        std::vector<uint8_t>& okm,
                        size_t L);

static void lexicographic_concat(const std::string& label,
                                 const std::vector<uint8_t>& a,
                                 const std::vector<uint8_t>& b,
                                 std::vector<uint8_t>& out);

static bool ed25519_seed_from_evp(EVP_PKEY* ed, std::vector<uint8_t>& seed_out);

static bool ed25519_seed_to_x25519_pair(const std::vector<uint8_t>& ed_seed,
                                        std::vector<uint8_t>& xpriv_out,
                                        std::vector<uint8_t>& xpub_out);

static bool convert_ed25519_to_x25519(EVP_PKEY* ed25519_key, EVP_PKEY** x25519_key_out);

static bool get_x25519_public_from_ed25519_priv(EVP_PKEY* ed_priv, std::vector<uint8_t>& out_xpub);

static bool derive_shared_secret(EVP_PKEY* my_key, const std::vector<uint8_t>& peer_pub, std::vector<uint8_t>& secret);


class ED25519 {
public:
    ED25519();
    ~ED25519();

    bool generate_keypair();

    bool get_public_key_pem(std::string& pem);
    bool get_private_key_pem(std::string& pem);

    bool set_public_key_pem(const std::string& pem);
    bool set_private_key_pem(const std::string& pem);

    bool export_public_key(const std::string& path);
    bool export_private_key(const std::string& path);
    
    bool import_private_key(const std::string& path);
    bool import_public_key(const std::string& path);

    bool export_public_key_bytes(std::vector<uint8_t>& pub) const;
    bool export_x25519_public_key_bytes(std::vector<uint8_t>& out) const;

    // Encrypt & Encode / Decode & decrypt
    bool encrypt(const std::string& plaintext, const std::vector<uint8_t>& peerPub, std::string& ciphertext);
    bool decrypt(const std::string& ciphertext, std::string& plaintext);

    bool encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& peerPub, std::vector<uint8_t>& ciphertext);
    bool decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext);

    // Sign & Encode / Decode & verify
    bool sign(const std::string& data, std::string& signature, const std::string& hash = "SHA384");
    bool verify(const std::string& data, const std::string& signature, const std::string& hash = "SHA384");

    bool sign(const std::vector<uint8_t>& data, std::vector<uint8_t>& signature, const std::string& hash = "SHA384");
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::string& hash = "SHA384");

private:
    //std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_;
    EVP_PKEY * ed25519_key_ = nullptr;
    static std::string get_openssl_error();
};

} // namespace iar::utils
