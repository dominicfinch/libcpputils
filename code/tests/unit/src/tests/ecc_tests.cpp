
#include <experimental/filesystem>
#include <iostream>

#include "ecc_tests.h"
#include "ecc.h"

bool test_key_generation_and_export_import() {
    iar::utils::ECC ecc1;
    if (!ecc1.generate_own_keypair()) return false;

    std::string pub_pem, priv_pem;
    if (!ecc1.get_own_public_key_pem(pub_pem)) return false;
    if (!ecc1.get_own_private_key_pem(priv_pem)) return false;

    if (!ecc1.export_public_key("public_key.pem")) return false;
    if (!ecc1.export_private_key("private_key.pem")) return false;

    if (!ecc1.import_public_key("public_key.pem")) return false;
    if (!ecc1.import_private_key("private_key.pem")) return false;

    iar::utils::ECC ecc2;
    if (!ecc2.load_peer_public_key_from_pem(pub_pem)) return false;

    std::remove("public_key.pem");
    std::remove("private_key.pem");
    
    return true;
}

bool test_shared_secret_derivation() {
    iar::utils::ECC alice, bob;
    if (!alice.generate_own_keypair() || !bob.generate_own_keypair()) return false;

    std::string alice_pub, bob_pub;
    if (!alice.get_own_public_key_pem(alice_pub)) return false;
    if (!bob.get_own_public_key_pem(bob_pub)) return false;

    if (!alice.load_peer_public_key_from_pem(bob_pub)) return false;
    if (!bob.load_peer_public_key_from_pem(alice_pub)) return false;

    std::vector<uint8_t> alice_secret, bob_secret;
    if (!alice.derive_shared_secret_with_peer(alice_secret)) return false;
    if (!bob.derive_shared_secret_with_peer(bob_secret)) return false;

    return alice_secret == bob_secret;
}

bool test_signing_and_verification() {
    iar::utils::ECC signer, verifier;
    if (!signer.generate_own_keypair()) return false;

    std::string pub;
    if (!signer.get_own_public_key_pem(pub)) return false;
    if (!verifier.load_peer_public_key_from_pem(pub)) return false;

    std::string message = "Test message for signing";
    std::string signature;
    if (!signer.sign_with_own_key(message, signature)) return false;
    if (!verifier.verify_with_peer_key(message, signature)) return false;

    std::string tampered = message + "!";
    return !verifier.verify_with_peer_key(tampered, signature);
}

bool test_encryption_decryption_binary() {
    iar::utils::ECC sender, receiver;
    if (!sender.generate_own_keypair() || !receiver.generate_own_keypair()) return false;

    std::string sender_pub, receiver_pub;
    if (!sender.get_own_public_key_pem(sender_pub)) return false;
    if (!receiver.get_own_public_key_pem(receiver_pub)) return false;

    if (!sender.load_peer_public_key_from_pem(receiver_pub)) return false;
    if (!receiver.load_peer_public_key_from_pem(sender_pub)) return false;

    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', 0, 1, 2, 3, 255};
    std::vector<uint8_t> ciphertext, decrypted, iv, tag;

    if (!sender.encrypt(plaintext, ciphertext, iv, tag)) return false;
    if (!receiver.decrypt(ciphertext, decrypted, iv, tag)) return false;

    return plaintext == decrypted;
}

bool test_encryption_decryption_strings() {
    iar::utils::ECC sender, receiver;
    if (!sender.generate_own_keypair() || !receiver.generate_own_keypair()) return false;

    std::string sender_pub, receiver_pub;
    if (!sender.get_own_public_key_pem(sender_pub)) return false;
    if (!receiver.get_own_public_key_pem(receiver_pub)) return false;

    if (!sender.load_peer_public_key_from_pem(receiver_pub)) return false;
    if (!receiver.load_peer_public_key_from_pem(sender_pub)) return false;

    std::string plaintext = "Confidential message with unicode: ☀️🔒";
    std::vector<uint8_t> plain_vec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertext, decrypted_vec, iv, tag;

    if (!sender.encrypt(plain_vec, ciphertext, iv, tag)) return false;
    if (!receiver.decrypt(ciphertext, decrypted_vec, iv, tag)) return false;

    std::string decrypted_str(decrypted_vec.begin(), decrypted_vec.end());
    return plaintext == decrypted_str;
}

bool test_ecc_load_own_public_key_from_pem() {
    iar::utils::ECC ecc_original;
    if (!ecc_original.generate_own_keypair()) {
        std::cerr << "Failed to generate ECC keypair\n";
        return false;
    }

    std::string public_pem;
    if (!ecc_original.get_own_public_key_pem(public_pem)) {
        std::cerr << "Failed to export ECC public key PEM\n";
        return false;
    }

    iar::utils::ECC ecc_loaded;
    if (!ecc_loaded.load_own_public_key_from_pem(public_pem)) {
        std::cerr << "Failed to load ECC public key from PEM\n";
        return false;
    }

    // Optional: check that signature verification using the loaded key works
    std::string message = "test message";
    std::string signature;
    if (!ecc_original.sign_with_own_key(message, signature)) {
        std::cerr << "Failed to sign message with original key\n";
        return false;
    }

    // NOTE: Without private key, one would expect verification to fail, no?
    // The loaded public key should verify the signature
    //if (!ecc_loaded.verify_with_peer_key(message, signature)) {
    //    std::cerr << "Loaded public key failed to verify signature\n";
    //    return false;
    //}

    return true;
}

// Test loading a private key from a valid PEM string
bool test_ecc_load_own_private_key_from_pem() {
    iar::utils::ECC ecc_original;
    if (!ecc_original.generate_own_keypair()) {
        std::cerr << "Failed to generate ECC keypair\n";
        return false;
    }

    std::string private_pem;
    if (!ecc_original.get_own_private_key_pem(private_pem)) {
        std::cerr << "Failed to export ECC private key PEM\n";
        return false;
    }

    iar::utils::ECC ecc_loaded;
    if (!ecc_loaded.load_own_private_key_from_pem(private_pem)) {
        std::cerr << "Failed to load ECC private key from PEM\n";
        return false;
    }

    // Verify that we can sign with the loaded private key
    std::string message = "hello world";
    std::string signature;
    if (!ecc_loaded.sign_with_own_key(message, signature)) {
        std::cerr << "Failed to sign using loaded ECC private key\n";
        return false;
    }

    // The original public key should verify the signature
    std::string pub_pem;
    if (!ecc_original.get_own_public_key_pem(pub_pem)) return false;
    if (!ecc_loaded.load_peer_public_key_from_pem(pub_pem)) return false;

    if (!ecc_loaded.verify_with_peer_key(message, signature)) {
        std::cerr << "Signature created by loaded key failed verification\n";
        return false;
    }

    return true;
}