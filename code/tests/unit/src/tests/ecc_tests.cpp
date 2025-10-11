
#include <experimental/filesystem>

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