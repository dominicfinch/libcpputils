
// test_chacha.cpp
#include "chacha.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>

bool test_chacha_generate_and_has_key() {
    iar::utils::ChaCha c;
    if (!c.generate_key()) return false;
    return c.has_key();
}

bool test_chacha_save_load_pem() {
    iar::utils::ChaCha c;
    if (!c.generate_key()) return false;
    const char* fname = "tmp_chacha_key.pem";
    if (!c.save_key_pem_file(fname)) return false;
    iar::utils::ChaCha d;
    if (!d.load_key_pem_file(fname)) return false;
    // cleanup
    std::remove(fname);
    std::vector<uint8_t> a, b;
    if (!c.get_raw_key(a)) return false;
    if (!d.get_raw_key(b)) return false;
    return a == b;
}

bool test_chacha_encrypt_decrypt_vector() {
    iar::utils::ChaCha alice, bob;
    if (!alice.generate_key()) return false;
    if (!bob.generate_key()) return false;

    // For symmetric iar::utils::ChaCha, both sides must share the same key.
    // In typical usage you'd share keys out-of-band; for test, copy bob's key to alice.
    std::vector<uint8_t> key;
    if (!bob.get_raw_key(key)) return false;
    if (!alice.set_raw_key(key)) return false;

    std::vector<uint8_t> msg = {'s','e','c','r','e','t'};
    std::vector<uint8_t> aad = {'a','a','d'};
    std::vector<uint8_t> ct, pt;

    if (!alice.encrypt(msg, aad, ct)) return false;
    if (!bob.decrypt(ct, aad, pt)) return false;
    return pt == msg;
}

bool test_chacha_encrypt_decrypt_string() {
    iar::utils::ChaCha alice, bob;
    if (!alice.generate_key()) return false;
    if (!bob.generate_key()) return false;

    std::vector<uint8_t> key;
    if (!bob.get_raw_key(key)) return false;
    if (!alice.set_raw_key(key)) return false;

    std::string msg = "secret message";
    std::string aad = "my-aad";
    std::string ct_b64, pt;

    if (!alice.encrypt(msg, aad, ct_b64)) return false;
    if (!bob.decrypt(ct_b64, aad, pt)) return false;
    return pt == msg;
}

bool test_chacha_tamper_detection() {
    iar::utils::ChaCha a;
    if (!a.generate_key()) return false;
    std::vector<uint8_t> key;
    if (!a.get_raw_key(key)) return false;

    std::vector<uint8_t> msg = {'a','b','c'};
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ct;
    if (!a.encrypt(msg, aad, ct)) return false;

    // Flip a byte in ciphertext body (after nonce)
    if (ct.size() > 13) ct[13] ^= 0xFF;

    iar::utils::ChaCha b;
    if (!b.set_raw_key(key)) return false;
    std::vector<uint8_t> out;
    bool ok = b.decrypt(ct, aad, out);
    return !ok; // should fail
}
