
#include "dh_tests.h"
#include "dh.h"

bool test_generate_parameters() {
    iar::utils::DiffieHellman dh;
    return dh.generate_parameters(2048);
}

bool test_generate_keypair() {
    iar::utils::DiffieHellman dh;
    return dh.generate_parameters(2048) && dh.generate_keypair();
}

bool test_get_set_parameters() {
    iar::utils::DiffieHellman dh1, dh2;
    if (!dh1.generate_parameters(2048)) return false;

    std::vector<uint8_t> params;
    if (!dh1.get_parameters(params)) return false;
    if (params.empty()) return false;

    if (!dh2.set_parameters(params)) return false;
    return true;
}

bool test_public_key_string_export() {
    iar::utils::DiffieHellman dh;
    if (!dh.generate_parameters(2048)) return false;
    if (!dh.generate_keypair()) return false;

    std::string pem;
    return dh.public_key(pem) && !pem.empty();
}

bool test_public_key_binary_export() {
    iar::utils::DiffieHellman dh;
    if (!dh.generate_parameters(2048)) return false;
    if (!dh.generate_keypair()) return false;

    std::vector<uint8_t> pubkey;
    return dh.public_key(pubkey) && !pubkey.empty();
}

bool test_set_peer_public_key_and_compute_shared_secret() {
    iar::utils::DiffieHellman dh1, dh2;
    if (!dh1.generate_parameters(2048)) return false;

    std::vector<uint8_t> params;
    if (!dh1.get_parameters(params)) return false;
    if (!dh2.set_parameters(params)) return false;
    
    if (!dh1.generate_keypair() || !dh2.generate_keypair()) return false;

    std::vector<uint8_t> pubkey1, pubkey2;
    if (!dh1.public_key(pubkey1) || !dh2.public_key(pubkey2)) return false;

    if (!dh1.set_peer_public_key(pubkey2)) return false;
    if (!dh2.set_peer_public_key(pubkey1)) return false;

    std::vector<uint8_t> secret1, secret2;
    if (!dh1.compute_shared_secret(secret1)) return false;
    if (!dh2.compute_shared_secret(secret2)) return false;

    return secret1 == secret2;
}

bool test_clear_keypair_resets_state() {
    iar::utils::DiffieHellman dh;
    if (!dh.generate_parameters(2048)) return false;
    if (!dh.generate_keypair()) return false;

    dh.clear_keypair();

    std::string pem;
    return !dh.public_key(pem); // Should fail as keypair is cleared
}



bool test_public_key_without_keypair() {
    iar::utils::DiffieHellman dh;
    std::string pem;
    return !dh.public_key(pem); // Should fail without keypair
}

bool test_set_invalid_peer_key() {
    iar::utils::DiffieHellman dh;
    std::vector<uint8_t> garbage_key = { 0x01, 0x02, 0x03 };
    return !dh.set_peer_public_key(garbage_key); // Should fail
}

bool test_compute_secret_without_peer_key() {
    iar::utils::DiffieHellman dh;
    if (!dh.generate_parameters(2048)) return false;
    if (!dh.generate_keypair()) return false;

    std::vector<uint8_t> secret;
    return !dh.compute_shared_secret(secret); // Should fail as no peer key set
}

bool test_compute_secret_without_keypair() {
    iar::utils::DiffieHellman dh;
    std::vector<uint8_t> secret;
    return !dh.compute_shared_secret(secret); // Should fail as no keypair generated
}
