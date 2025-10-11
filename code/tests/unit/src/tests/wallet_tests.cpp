
#include "wallet_tests.h"
#include "hex.h"
#include "wallet.h"

#include <iostream>
#include <string>
#include <vector>
#include <cassert>

bool test_key_generation() {
    iar::utils::CryptoWallet wallet;
    return wallet.generate_wallet_key("prime256v1");
}

bool test_key_extraction() {
    iar::utils::CryptoWallet wallet;
    if (!wallet.generate_wallet_key()) return false;

    std::string pub_hex, priv_hex;
    return wallet.public_key(pub_hex) && wallet.private_key(priv_hex)
        && wallet.private_key(priv_hex) && !pub_hex.empty() && !priv_hex.empty();
}

bool test_key_public_key_export() {
    iar::utils::CryptoWallet wallet;
    std::string curve = "prime256v1";
    std::string encodedPrivateKey = "30770201010420905fb65e46d16f5ad641976fc44e2a72addfa29027bfdd246094f8a0b9f208c3a00a06082a8648ce3d030107a1440342000449d2109f80e6541c41898096b805f1c947e84d0896ff17fafc9a6038e21781758c47da417dc37d64343c0f82b2295e858200f95c080ca0135cb84b7c34824a8e";
    std::string expectedPublicKey = "0449d2109f80e6541c41898096b805f1c947e84d0896ff17fafc9a6038e21781758c47da417dc37d64343c0f82b2295e858200f95c080ca0135cb84b7c34824a8e";
    std::string publicKey;

    if(!wallet.import_key(encodedPrivateKey, curve)) return false;
    if(!wallet.public_key(publicKey)) return false;
    return publicKey == expectedPublicKey;
}

bool test_key_private_key_import() {
    iar::utils::CryptoWallet wallet;
    std::string curve = "prime256v1";
    if(!wallet.generate_wallet_key(curve)) return false;

    std::string encodedPrivateKey;
    if(!wallet.private_key(encodedPrivateKey)) return false;
    return wallet.import_key(encodedPrivateKey, curve);
}

bool test_wallet_address() {
    iar::utils::CryptoWallet wallet;
    std::string curve = "prime256v1";
    // Fixing private key so expected wallet address becomes deterministic
    std::string encodedPrivateKey = "30770201010420905fb65e46d16f5ad641976fc44e2a72addfa29027bfdd246094f8a0b9f208c3a00a06082a8648ce3d030107a1440342000449d2109f80e6541c41898096b805f1c947e84d0896ff17fafc9a6038e21781758c47da417dc37d64343c0f82b2295e858200f95c080ca0135cb84b7c34824a8e";
    std::string expectedWalletAddress = "1BkqdWDpryQ7XFoCwyb3RQgk9oJvk1oyPC";
    std::string walletAddress;

    if(!wallet.import_key(encodedPrivateKey, curve)) return false;

    if(!wallet.wallet_address(walletAddress)) return false;
    return walletAddress == expectedWalletAddress;
}

bool test_sign_and_verify_string() {
    iar::utils::CryptoWallet wallet;
    if (!wallet.generate_wallet_key()) return false;

    std::string message = "Hello World!";
    std::string signature;
    if (!wallet.sign(message, signature)) return false;
    return wallet.verify(message, signature);
}

bool test_sign_and_verify_binary() {
    iar::utils::CryptoWallet wallet;
    if (!wallet.generate_wallet_key()) return false;

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> signature;
    if (!wallet.sign(message, signature)) return false;
    return wallet.verify(message, signature);
}

bool test_encrypt_decrypt_string_prime256v1() {
    iar::utils::CryptoWallet sender, receiver;
    if (!sender.generate_wallet_key("prime256v1") || !receiver.generate_wallet_key("prime256v1")) return false;

    std::vector<uint8_t> receiver_pub;
    std::vector<uint8_t> sender_pub;
    if (!receiver.public_key(receiver_pub)) return false;
    if (!sender.public_key(sender_pub)) return false;

    std::string plaintext = "Test encryption message!";
    std::string ciphertext; std::string tag;
    std::vector<uint8_t> iv;

    if (!sender.encrypt(plaintext, ciphertext, tag, receiver_pub, iv, "prime256v1")) return false;
    
    std::string decrypted;
    return receiver.decrypt(ciphertext, decrypted, tag, sender_pub, iv, "prime256v1") && decrypted == plaintext;
}

bool test_encrypt_decrypt_string_secp384r1() {
    iar::utils::CryptoWallet sender, receiver;
    if (!sender.generate_wallet_key("secp384r1") || !receiver.generate_wallet_key("secp384r1")) return false;

    std::vector<uint8_t> receiver_pub;
    std::vector<uint8_t> sender_pub;
    if (!receiver.public_key(receiver_pub)) return false;
    if (!sender.public_key(sender_pub)) return false;

    std::string plaintext = "Test encryption message!";
    std::string ciphertext; std::string tag;
    std::vector<uint8_t> iv;

    if (!sender.encrypt(plaintext, ciphertext, tag, receiver_pub, iv, "secp384r1")) return false;
    
    std::string decrypted;
    return receiver.decrypt(ciphertext, decrypted, tag, sender_pub, iv, "secp384r1") && decrypted == plaintext;
}

bool test_encrypt_decrypt_string_secp521r1() {
    iar::utils::CryptoWallet sender, receiver;
    if (!sender.generate_wallet_key("secp521r1") || !receiver.generate_wallet_key("secp521r1")) return false;

    std::vector<uint8_t> receiver_pub;
    std::vector<uint8_t> sender_pub;
    if (!receiver.public_key(receiver_pub)) return false;
    if (!sender.public_key(sender_pub)) return false;

    std::string plaintext = "Test encryption message!";
    std::string ciphertext; std::string tag;
    std::vector<uint8_t> iv;

    if (!sender.encrypt(plaintext, ciphertext, tag, receiver_pub, iv, "secp521r1")) return false;
    
    std::string decrypted;
    return receiver.decrypt(ciphertext, decrypted, tag, sender_pub, iv, "secp521r1") && decrypted == plaintext;
}

bool test_encrypt_decrypt_binary() {
    iar::utils::CryptoWallet sender, receiver;
    if (!sender.generate_wallet_key() || !receiver.generate_wallet_key()) return false;

    std::vector<uint8_t> receiver_pub;
    std::vector<uint8_t> sender_pub;
    if (!receiver.public_key(receiver_pub)) return false;
    if (!sender.public_key(sender_pub)) return false;

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5, 6, 7};
    std::vector<uint8_t> ciphertext; std::vector<uint8_t> tag;
    std::vector<uint8_t> iv;

    if (!sender.encrypt(plaintext, ciphertext, tag, receiver_pub, iv)) return false;

    std::vector<uint8_t> decrypted;
    if (!receiver.decrypt(ciphertext, decrypted, tag, sender_pub, iv)) return false;

    return decrypted == plaintext;
}