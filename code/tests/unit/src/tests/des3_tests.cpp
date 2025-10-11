#include "des3_tests.h"
#include "des3.h"

#include <iostream>
#include <random>
#include <cstring>
#include <algorithm>

// Helper to generate random bytes
std::vector<uint8_t> random_bytes(size_t length) {
    std::vector<uint8_t> data(length);
    std::random_device rd;
    std::generate(data.begin(), data.end(), [&]() { return static_cast<uint8_t>(rd()); });
    return data;
}

// =========================
// CBC Mode Tests
// =========================

bool test_des3_cbc_encrypt_decrypt() {
    iar::utils::DES3 des3(iar::utils::DES3Mode::CBC);

    auto key = random_bytes(24);
    auto iv  = random_bytes(8);
    if (!des3.set_key(key, iv)) return false;

    std::vector<uint8_t> plaintext = {'H','e','l','l','o',' ','D','E','S','3'};
    std::vector<uint8_t> ciphertext, decrypted;

    if (!des3.encrypt(plaintext, ciphertext)) return false;
    if (!des3.decrypt(ciphertext, decrypted)) return false;

    return decrypted == plaintext;
}

bool test_des3_cbc_invalid_key_size() {
    iar::utils::DES3 des3(iar::utils::DES3Mode::CBC);
    std::vector<uint8_t> bad_key(16);  // Too short
    std::vector<uint8_t> iv(8);
    return !des3.set_key(bad_key, iv);
}

bool test_des3_cbc_invalid_iv_size() {
    iar::utils::DES3 des3(iar::utils::DES3Mode::CBC);
    std::vector<uint8_t> key(24);
    std::vector<uint8_t> bad_iv(5);
    return !des3.set_key(key, bad_iv);
}

// =========================
// ECB Mode Tests
// =========================

bool test_des3_ecb_encrypt_decrypt() {
    iar::utils::DES3 des3(iar::utils::DES3Mode::ECB);
    auto key = random_bytes(24);
    if (!des3.set_key(key)) return false;

    std::vector<uint8_t> plaintext = {'S','e','c','r','e','t','!','!'};
    std::vector<uint8_t> ciphertext, decrypted;

    if (!des3.encrypt(plaintext, ciphertext)) return false;
    if (!des3.decrypt(ciphertext, decrypted)) return false;

    return decrypted == plaintext;
}

bool test_des3_ecb_reject_iv() {
    iar::utils::DES3 des3(iar::utils::DES3Mode::ECB);
    auto key = random_bytes(24);
    auto iv = random_bytes(8);
    // Should ignore IV or reject depending on implementation – here, we test rejection.
    return !des3.set_key(key, iv);  // Our implementation treats it as invalid
}

// =========================
// Edge Cases
// =========================

bool test_des3_encrypt_without_key() {
    iar::utils::DES3 des3;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext = {'a','b','c'};
    return !des3.encrypt(plaintext, ciphertext);
}

bool test_des3_decrypt_without_key() {
    iar::utils::DES3 des3;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext = {'x','y','z'};
    return !des3.decrypt(ciphertext, plaintext);
}

bool test_des3_clear_resets_state() {
    iar::utils::DES3 des3;
    auto key = random_bytes(24);
    auto iv = random_bytes(8);
    if (!des3.set_key(key, iv)) return false;
    des3.clear();
    std::vector<uint8_t> plaintext = {'1','2','3'};
    std::vector<uint8_t> out;
    return !des3.encrypt(plaintext, out);
}