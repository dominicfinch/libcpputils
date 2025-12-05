/*
 © Copyright 2025 Dominic Finch
*/

#include "chacha.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>

#include "base64.h"

using std::size_t;

namespace iar { namespace utils {

static std::string openssl_error_string() {
    unsigned long e = ERR_get_error();
    if (e == 0) return std::string();
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

ChaCha::ChaCha() = default;
ChaCha::~ChaCha() { clear_key(); }

ChaCha::ChaCha(ChaCha&& o) noexcept : key_(std::move(o.key_)) { o.clear_key(); }
ChaCha& ChaCha::operator=(ChaCha&& o) noexcept { if (this != &o) { key_ = std::move(o.key_); o.clear_key(); } return *this; }

bool ChaCha::generate_key() {
    key_.assign(32, 0);
    if (RAND_bytes(key_.data(), (int)key_.size()) != 1) {
        key_.clear();
        return false;
    }
    return true;
}

bool ChaCha::has_key() const { return key_.size() == 32; }

bool ChaCha::get_raw_key(std::vector<uint8_t>& out) const {
    if (!has_key()) return false;
    out = key_;
    return true;
}

bool ChaCha::set_raw_key(const std::vector<uint8_t>& key) {
    if (key.size() != 32) return false;
    key_ = key;
    return true;
}

void ChaCha::clear_key() {
    if (!key_.empty()) {
        OPENSSL_cleanse(key_.data(), key_.size());
        key_.clear();
    }
}

// ---------------- PEM armor helpers ----------------

std::string ChaCha::pem_wrap(const std::string& b64, const std::string& header, const std::string& footer) {
    std::ostringstream oss;
    oss << header << "\n";
    // wrap at 64 columns
    for (size_t i = 0; i < b64.size(); i += 64) {
        oss << b64.substr(i, std::min<size_t>(64, b64.size() - i)) << "\n";
    }
    oss << footer << "\n";
    return oss.str();
}

bool ChaCha::pem_unwrap(const std::string& pem, std::string& b64_out, const std::string& header, const std::string& footer) {
    std::istringstream iss(pem);
    std::string line;
    bool in_block = false;
    b64_out.clear();
    while (std::getline(iss, line)) {
        if (!in_block) {
            if (line == header) in_block = true;
        } else {
            if (line == footer) return true;
            // trim whitespace
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
            b64_out += line;
        }
    }
    return false;
}

// ---------------- PEM file save/load ----------------

bool ChaCha::get_key_pem(std::string& out_pem) const {
    if (!has_key()) return false;
    std::string b64 = Base64::encode(key_);
    out_pem = pem_wrap(b64, "-----BEGIN CHACHA20-POLY1305 KEY-----", "-----END CHACHA20-POLY1305 KEY-----");
    return true;
}

bool ChaCha::set_key_pem(const std::string& pem) {
    std::string b64;
    if (!pem_unwrap(pem, b64, "-----BEGIN CHACHA20-POLY1305 KEY-----", "-----END CHACHA20-POLY1305 KEY-----")) return false;
    std::vector<uint8_t> raw = Base64::decode(b64);
    if (raw.size() != 32) return false;
    key_ = raw;
    return true;
}

bool ChaCha::save_key_pem_file(const std::string& path) const {
    std::string pem;
    if (!get_key_pem(pem)) return false;
    std::ofstream ofs(path, std::ios::out | std::ios::binary);
    if (!ofs) return false;
    ofs << pem;
    return ofs.good();
}

bool ChaCha::load_key_pem_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::in | std::ios::binary);
    if (!ifs) return false;
    std::ostringstream ss;
    ss << ifs.rdbuf();
    std::string pem = ss.str();
    return set_key_pem(pem);
}

// ---------------- Encryption / Decryption ----------------

bool ChaCha::encrypt(const std::vector<uint8_t>& plaintext,
                     const std::vector<uint8_t>& aad,
                     std::vector<uint8_t>& ciphertext) const
{
    if (!has_key()) return false;

    // nonce 12 bytes
    std::vector<uint8_t> nonce(12);
    if (RAND_bytes(nonce.data(), (int)nonce.size()) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    std::vector<uint8_t> outbuf(plaintext.size());
    int outlen = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, plaintext.data(), (int)plaintext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    } else outlen = 0;

    int outlen_final = 0;
    if (EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen, &outlen_final) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    outlen += outlen_final;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)sizeof(tag), tag) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    EVP_CIPHER_CTX_free(ctx);

    // build ciphertext = nonce || outbuf[0:outlen] || tag
    ciphertext.clear();
    ciphertext.reserve(nonce.size() + outlen + sizeof(tag));
    ciphertext.insert(ciphertext.end(), nonce.begin(), nonce.end());
    ciphertext.insert(ciphertext.end(), outbuf.begin(), outbuf.begin() + outlen);
    ciphertext.insert(ciphertext.end(), tag, tag + sizeof(tag));

    return true;
}

bool ChaCha::decrypt(const std::vector<uint8_t>& ciphertext,
                     const std::vector<uint8_t>& aad,
                     std::vector<uint8_t>& plaintext) const
{
    if (!has_key()) return false;
    const size_t nonce_len = 12;
    const size_t tag_len = 16;
    if (ciphertext.size() < nonce_len + tag_len) return false;

    const uint8_t* ptr = ciphertext.data();
    const uint8_t* nonce_ptr = ptr; ptr += nonce_len;
    size_t body_len = ciphertext.size() - nonce_len - tag_len;
    const uint8_t* body_ptr = ptr; ptr += body_len;
    const uint8_t* tag_ptr = ptr;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce_ptr) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    plaintext.resize(body_len);
    int outlen = 0;
    if (body_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, body_ptr, (int)body_len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    } else outlen = 0;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, (void*)tag_ptr) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    int outlen_final = 0;
    int rv = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen_final);
    EVP_CIPHER_CTX_free(ctx);

    if (rv != 1)  
        return false;   // authentication failure

    plaintext.resize(outlen); // final adds 0 bytes for ChaCha20-Poly1305
    return true;
}

// ---------------- String overloads (Base64) ----------------

bool ChaCha::encrypt(const std::string& plaintext,
                     const std::string& aad,
                     std::string& ciphertext_b64) const
{
    std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
    //std::vector<uint8_t> a(adjust(aad));
    // can't call adjust; do direct:
    std::vector<uint8_t> aa(aad.begin(), aad.end());

    std::vector<uint8_t> ct;
    if (!encrypt(pt, aa, ct)) return false;
    ciphertext_b64 = Base64::encode(ct);
    return true;
}

bool ChaCha::decrypt(const std::string& ciphertext_b64,
                     const std::string& aad,
                     std::string& plaintext) const
{
    std::vector<uint8_t> ct = Base64::decode(ciphertext_b64);
    std::vector<uint8_t> aa(aad.begin(), aad.end());
    std::vector<uint8_t> pt;
    if (!decrypt(ct, aa, pt)) return false;
    plaintext.assign(pt.begin(), pt.end());
    return true;
}

}}