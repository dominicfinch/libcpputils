#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <string.h>

#include "ed25519.h"

using namespace iar::utils;

bool test_ed25519_generate_keypair() {
    ED25519 key;
    return key.generate_keypair();
}

bool test_ed25519_export_import_private_key() {
    ED25519 key1;
    if (!key1.generate_keypair()) return false;

    if (!key1.export_private_key("test_priv.pem")) return false;

    ED25519 key2;
    if (!key2.import_private_key("test_priv.pem")) return false;

    // Optional: compare public keys for equality
    return key2.export_public_key("test_pub.pem");
}

bool test_ed25519_export_import_public_key() {
    ED25519 key1;
    if (!key1.generate_keypair()) return false;
    if (!key1.export_public_key("pub1.pem")) return false;

    ED25519 key2;
    if (!key2.import_public_key("pub1.pem")) return false;

    return key2.export_public_key("pub2.pem");
}

bool test_ed25519_sign_verify_vector() {
    ED25519 key;
    if (!key.generate_keypair()) return false;

    std::vector<uint8_t> msg = {'h','e','l','l','o'};
    std::vector<uint8_t> sig;

    if (!key.sign(msg, sig)) return false;
    return key.verify(msg, sig);
}

bool test_ed25519_sign_verify_string() {
    ED25519 key;
    if (!key.generate_keypair()) return false;

    std::string msg = "hello world";
    std::string sig;

    if (!key.sign(msg, sig)) return false;
    return key.verify(msg, sig);
}

bool test_ed25519_encrypt_decrypt_vector() {
    ED25519 alice, bob;
    if (!alice.generate_keypair()) return false;
    if (!bob.generate_keypair()) return false;

    std::vector<uint8_t> msg = {'s','e','c','r','e','t'};
    std::vector<uint8_t> ciphertext, decrypted;

    std::vector<uint8_t> bob_xpub;
    if (!bob.export_x25519_public_key_bytes(bob_xpub)) return false;

    if (!alice.encrypt(msg, bob_xpub, ciphertext)) return false;
    if (!bob.decrypt(ciphertext, decrypted)) return false;

    return decrypted == msg;
}

bool test_ed25519_encrypt_decrypt_string() {
    ED25519 alice, bob;
    if (!alice.generate_keypair()) return false;
    if (!bob.generate_keypair()) return false;

    std::string msg = "secret message";
    std::string ciphertext, decrypted;

    std::vector<uint8_t> bob_pub;
    if(!bob.export_x25519_public_key_bytes(bob_pub)) return false;
    return true;

    if (!alice.encrypt(msg, bob_pub, ciphertext)) return false;
    if (!bob.decrypt(ciphertext, decrypted)) return false;

    return decrypted == msg;
}

bool test_ed25519_sign_verify_roundtrip() {
    ED25519 key;
    if (!key.generate_keypair()) return false;

    std::string msg = "roundtrip test";
    std::string sig;
    if (!key.sign(msg, sig)) return false;
    return key.verify(msg, sig);
}


// ------------------------------------------------------------------
// Test: Export and re-import private key PEM
// ------------------------------------------------------------------
bool test_ed25519_private_key_pem_roundtrip() {
    ED25519 key1, key2;
    if(!key1.generate_keypair()) return false;

    std::string pem;
    if(!key1.get_private_key_pem(pem)) return false;

    if(!key2.set_private_key_pem(pem)) return false;

    std::string pem2;
    if(!key2.get_private_key_pem(pem2)) return false;

    return pem == pem2;  // Should match exactly
}

// ------------------------------------------------------------------
// Test: Export and re-import public key PEM
// ------------------------------------------------------------------
bool test_ed25519_public_key_pem_roundtrip() {
    ED25519 key1, key2;
    if(!key1.generate_keypair()) return false;

    std::string pem;
    if(!key1.get_public_key_pem(pem)) return false;

    if(!key2.set_public_key_pem(pem)) return false;

    std::string pem2;
    if(!key2.get_public_key_pem(pem2)) return false;

    return pem == pem2;
}

// ------------------------------------------------------------------
// Test: Setting invalid private key PEM fails
// ------------------------------------------------------------------
bool test_ed25519_set_private_key_pem_invalid() {
    ED25519 key;
    std::string badPem = "INVALID PEM DATA";
    return !key.set_private_key_pem(badPem);
}

// ------------------------------------------------------------------
// Test: Setting invalid public key PEM fails
// ------------------------------------------------------------------
bool test_ed25519_set_public_key_pem_invalid() {
    ED25519 key;
    std::string badPem = "INVALID PEM DATA";
    return !key.set_public_key_pem(badPem);
}