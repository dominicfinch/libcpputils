#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>

#include "ecdsa.h"

using namespace iar::utils;

static std::string tmpfile_path(const std::string& name) {
    return "/tmp/" + name;
}

bool test_ecdsa_generate_keypair_and_export_import() {
    ECDSA ecdsa;
    if (!ecdsa.generate_keypair(384))
        return false;

    std::string priv_path = tmpfile_path("ecdsa_priv.pem");
    std::string pub_path  = tmpfile_path("ecdsa_pub.pem");

    if (!ecdsa.export_private_key(priv_path))
        return false;
    if (!ecdsa.export_public_key(pub_path))
        return false;

    ECDSA ecdsa2;
    if (!ecdsa2.import_private_key(priv_path))
        return false;
    if (!ecdsa2.import_public_key(pub_path))
        return false;

    return true;
}

bool test_ecdsa_sign_and_verify_sha384() {
    ECDSA ecdsa;
    if (!ecdsa.generate_keypair(384))
        return false;

    std::vector<uint8_t> message = {'h','e','l','l','o'};
    std::vector<uint8_t> sig;

    if (!ecdsa.sign(message, sig, "SHA384"))
        return false;

    return ecdsa.verify(message, sig, "SHA384");
}

bool test_ecdsa_sign_and_verify_sha512() {
    ECDSA ecdsa;
    if (!ecdsa.generate_keypair(521))
        return false;

    std::vector<uint8_t> message = {'O','p','e','n','S','S','L','3'};
    std::vector<uint8_t> sig;

    if (!ecdsa.sign(message, sig, "SHA512"))
        return false;

    return ecdsa.verify(message, sig, "SHA512");
}

bool test_ecdsa_import_invalid_key() {
    ECDSA ecdsa;
    // Try loading an invalid path
    return !ecdsa.import_private_key("/nonexistent/key.pem");
}

bool test_ecdsa_export_without_key() {
    ECDSA ecdsa; // no key generated
    std::string pub_path = tmpfile_path("ecdsa_fail.pem");
    return !ecdsa.export_public_key(pub_path);
}

bool test_ecdsa_verify_fails_on_wrong_signature() {
    ECDSA ecdsa;
    if (!ecdsa.generate_keypair(384))
        return false;

    std::vector<uint8_t> msg = {'d','a','t','a'};
    std::vector<uint8_t> sig;
    ecdsa.sign(msg, sig, "SHA384");

    // modify signature to make it invalid
    if (!sig.empty()) sig[0] ^= 0xFF;

    return !ecdsa.verify(msg, sig, "SHA384");
}

bool test_ecdsa_generate_invalid_bits() {
    ECDSA ecdsa;
    return !ecdsa.generate_keypair(123); // unsupported bit size
}
