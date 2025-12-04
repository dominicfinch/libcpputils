#pragma once
// ChaCha.h - ChaCha20-Poly1305 helper (OpenSSL 3.0+)
// Provides symmetric key generation, encrypt/decrypt, file PEM export/import,
// and convenient string/vector overloads.
//
// Requires OpenSSL 3.0+

#include <string>
#include <vector>
#include <cstdint>

namespace iar { namespace utils {

class ChaCha {
public:
    ChaCha();
    ~ChaCha();

    // Non-copyable, movable
    ChaCha(const ChaCha&) = delete;
    ChaCha& operator=(const ChaCha&) = delete;
    ChaCha(ChaCha&&) noexcept;
    ChaCha& operator=(ChaCha&&) noexcept;

    // Key management
    bool generate_key(); // generate a 32-byte random key
    bool has_key() const;

    // Save/load key to PEM-like file (base64 armored)
    bool save_key_pem_file(const std::string& path) const;
    bool load_key_pem_file(const std::string& path);

    // Get/Set key as PEM-armored string
    bool get_key_pem(std::string& out_pem) const;
    bool set_key_pem(const std::string& pem);

    // Raw key get/set
    bool get_raw_key(std::vector<uint8_t>& out) const;
    bool set_raw_key(const std::vector<uint8_t>& key);

    // Encrypt / Decrypt (binary)
    // ciphertext layout: [12-byte nonce][cipher bytes][16-byte tag]
    bool encrypt(const std::vector<uint8_t>& plaintext,
                 const std::vector<uint8_t>& aad,
                 std::vector<uint8_t>& ciphertext) const;

    bool decrypt(const std::vector<uint8_t>& ciphertext,
                 const std::vector<uint8_t>& aad,
                 std::vector<uint8_t>& plaintext) const;

    // Convenience string overloads: produce/consume Base64 ciphertext string
    bool encrypt(const std::string& plaintext,
                 const std::string& aad,
                 std::string& ciphertext_b64) const;

    bool decrypt(const std::string& ciphertext_b64,
                 const std::string& aad,
                 std::string& plaintext) const;

    // Clear key from memory
    void clear_key();

private:
    std::vector<uint8_t> key_; // 32 bytes when set

    static std::string pem_wrap(const std::string& b64, const std::string& header, const std::string& footer);
    static bool pem_unwrap(const std::string& pem, std::string& b64_out, const std::string& header, const std::string& footer);
};

}}