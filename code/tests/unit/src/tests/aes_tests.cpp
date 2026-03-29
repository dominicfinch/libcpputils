
#include <iostream>
#include <cassert>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <openssl/rand.h>

#include "aes_tests.h"
#include "aes.h"

bool test_aes_key_file_import()
{
    auto pwd = std::filesystem::current_path().u8string();
    auto key_filepath = pwd + "/data/aes.key";
    
    cpp::utils::AES aes;
    return aes.import_key(key_filepath);
}

bool test_aes_key_generation_export_import() {
    cpp::utils::AES aes1, aes2;

    if (!aes1.generate_key())
        return false;

    std::string key_hex = aes1.hex_encoded_key();
    std::string salt_hex = aes1.hex_encoded_salt();

    if (!aes1.export_key("test_key.dat"))
        return false;

    if (!aes2.import_key("test_key.dat"))
        return false;

    if (aes1.hex_encoded_key() != aes2.hex_encoded_key())
        return false;

    if (aes1.hex_encoded_salt() != aes2.hex_encoded_salt())
        return false;

    //std::remove("test_key.dat");
    return true;
}

bool test_aes_encrypt_decrypt_string_gcm() {
    cpp::utils::AES aes;
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, decrypted;

    if (!aes.encrypt(plaintext, ciphertext)) return false;
    if (!aes.decrypt(ciphertext, decrypted)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_string_cbc() {
    cpp::utils::AES aes;

    aes.set_mode(cpp::utils::AESMode::CBC);
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, decrypted;

    if (!aes.encrypt(plaintext, ciphertext)) return false;
    if (!aes.decrypt(ciphertext, decrypted)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_string_ecb() {
    cpp::utils::AES aes;

    aes.set_mode(cpp::utils::AESMode::ECB);
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, decrypted;

    if (!aes.encrypt(plaintext, ciphertext)) return false;
    if (!aes.decrypt(ciphertext, decrypted)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_string_cfb() {
    cpp::utils::AES aes;

    aes.set_mode(cpp::utils::AESMode::CFB);
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, tag, decrypted;

    if (!aes.encrypt(plaintext, ciphertext)) return false;
    if (!aes.decrypt(ciphertext, decrypted)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_binary_low_level_gcm()
{
    cpp::utils::AES aes;

    // Generate master key first
    if (!aes.generate_key()) {  // 256-bit AES key
        std::cerr << "Failed to generate AES key" << std::endl;
        return false;
    }

    // Sample plaintext
    std::vector<uint8_t> plaintext = {1,2,3,4,5,6,7,8,9,10};
    
    // Allocate per-message salt & IV
    std::vector<uint8_t> salt(16);
    std::vector<uint8_t> iv(12);

    if (RAND_bytes(salt.data(), salt.size()) != 1) return false;
    if (RAND_bytes(iv.data(), iv.size()) != 1) return false;

    std::vector<uint8_t> ciphertext, decrypted, tag, session_key;

    // Encrypt
    if (!aes.encrypt(plaintext, salt, iv, ciphertext, &tag, session_key)) {
        std::cerr << "Low-level encryption failed" << std::endl;
        return false;
    }

    // Ensure ciphertext is non-empty
    assert(!ciphertext.empty());

    // Decrypt
    std::vector<uint8_t> decrypted_session_key;
    if (!aes.decrypt(ciphertext, salt, iv, &tag, decrypted, decrypted_session_key)) {
        std::cerr << "Low-level decryption failed" << std::endl;
        return false;
    }

    // Verify plaintext matches decrypted
    if (decrypted != plaintext) {
        std::cerr << "Decrypted plaintext does not match original" << std::endl;
        return false;
    }

    return session_key == decrypted_session_key;
}

bool test_aes_encrypt_decrypt_binary_low_level_ecb()
{
    cpp::utils::AES aes;
    aes.set_mode(cpp::utils::AESMode::ECB);
    aes.generate_key();

    std::vector<uint8_t> salt(16), iv;
    RAND_bytes(salt.data(), salt.size());
    RAND_bytes(iv.data(), iv.size());

    std::vector<uint8_t> msg = {1,2,3,4,5};
    std::vector<uint8_t> ct, pt, sk1, sk2;

    if (!aes.encrypt(msg, salt, iv, ct, nullptr, sk1)) return false;
    if (!aes.decrypt(ct, salt, iv, nullptr, pt, sk2)) return false;

    return pt == msg;
}

bool test_aes_encrypt_decrypt_binary_low_level_cbc()
{
    cpp::utils::AES aes;
    aes.set_mode(cpp::utils::AESMode::CBC);
    aes.generate_key();

    std::vector<uint8_t> salt(16), iv(16);
    RAND_bytes(salt.data(), salt.size());
    RAND_bytes(iv.data(), iv.size());

    std::vector<uint8_t> msg = {'c','b','c','t','e','s','t'};
    std::vector<uint8_t> ct, pt, sk1, sk2;

    if (!aes.encrypt(msg, salt, iv, ct, nullptr, sk1)) return false;
    if (!aes.decrypt(ct, salt, iv, nullptr, pt, sk2)) return false;

    return pt == msg;
}

bool test_aes_encrypt_decrypt_binary_low_level_cfb()
{
    cpp::utils::AES aes;
    aes.set_mode(cpp::utils::AESMode::CFB);
    aes.generate_key();

    std::vector<uint8_t> salt(16), iv(16);
    RAND_bytes(salt.data(), salt.size());
    RAND_bytes(iv.data(), iv.size());

    std::vector<uint8_t> msg = {'c','f','b'};
    std::vector<uint8_t> ct, pt, sk1, sk2;

    if (!aes.encrypt(msg, salt, iv, ct, nullptr, sk1)) return false;
    if (!aes.decrypt(ct, salt, iv, nullptr, pt, sk2)) return false;

    return pt == msg;
}

bool test_aes_encrypt_decrypt_binary() {
    cpp::utils::AES aes;
    if (!aes.generate_key())
        return false;

    std::vector<uint8_t> input = {10, 20, 30, 40, 50};
    std::vector<uint8_t> encrypted, decrypted;

    if (!aes.encrypt(input, encrypted))
        return false;

    if (!aes.decrypt(encrypted, decrypted))
        return false;

    return decrypted == input;
}

bool test_aes_encrypt_decrypt_file() {
    cpp::utils::AES aes;
    if (!aes.generate_key())
        return false;

    std::string input_text = "Sensitive file contents";
    std::ofstream("aes_input.txt") << input_text;

    if (!aes.encrypt_file("aes_input.txt", "aes_output.enc"))
        return false;

    if (!aes.decrypt_file("aes_output.enc", "aes_output.txt"))
        return false;

    std::ifstream decrypted("aes_output.txt");
    std::string result((std::istreambuf_iterator<char>(decrypted)), std::istreambuf_iterator<char>());

    std::remove("aes_input.txt");
    std::remove("aes_output.enc");
    std::remove("aes_output.txt");
    std::remove("aes_tag.dat");

    return result == input_text;
}
/*
bool test_aes_encrypt_decrypt_stream() {
    cpp::utils::AES aes;
    if (!aes.generate_key()) return false;

    std::string input_text = "This is stream-based cpp::utils::AES encryption test.";
    std::istringstream in_stream(input_text);
    std::ostringstream encrypted_stream, decrypted_stream, tag_stream;

    if (!aes.encrypt_stream(in_stream, encrypted_stream, &tag_stream)) return false;

    std::istringstream encrypted_input(encrypted_stream.str());
    std::istringstream tag_input(tag_stream.str());

    if (!aes.decrypt_stream(encrypted_input, decrypted_stream, &tag_input)) return false;
    return input_text == decrypted_stream.str();
}

bool test_aes_decrypt_tampered_ciphertext_fails() {
    cpp::utils::AES aes;
    if (!aes.generate_key()) return false;

    std::string plaintext = "Secret message!";
    std::string ciphertext, tag;

    if (!aes.encrypt(plaintext, ciphertext, tag)) return false;

    // Tamper ciphertext (flip a bit)
    if (!ciphertext.empty())
        ciphertext[5] ^= 0xFF;

    std::string decrypted;
    return !aes.decrypt(ciphertext, decrypted, tag); // Expect decryption to fail
}
*/
