
#include <iostream>
#include <fstream>
#include <experimental/filesystem>

#include "aes_tests.h"
#include "aes.h"

bool test_aes_key_generation_export_import() {
    iar::utils::AES aes1, aes2;

    if (!aes1.generate_key())
        return false;

    std::string key_hex = aes1.hex_encoded_key();
    std::string iv_hex = aes1.hex_encoded_iv();

    if (!aes1.export_key("test_key.dat"))
        return false;

    if (!aes2.import_key("test_key.dat"))
        return false;

    if (aes1.hex_encoded_key() != aes2.hex_encoded_key())
        return false;

    if (aes1.hex_encoded_iv() != aes2.hex_encoded_iv())
        return false;

    std::remove("test_key.dat");
    return true;
}

bool test_aes_encrypt_decrypt_string_gcm() {
    iar::utils::AES aes;
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, tag, decrypted;

    if (!aes.encrypt(plaintext, ciphertext, tag)) return false;
    if (!aes.decrypt(ciphertext, decrypted, tag)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_string_cbc() {
    iar::utils::AES aes;

    aes.set_mode(iar::utils::AESMode::CBC);
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, tag, decrypted;

    if (!aes.encrypt(plaintext, ciphertext, tag)) return false;
    if (!aes.decrypt(ciphertext, decrypted, tag)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_string_ecb() {
    iar::utils::AES aes;

    aes.set_mode(iar::utils::AESMode::ECB);
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, tag, decrypted;

    if (!aes.encrypt(plaintext, ciphertext, tag)) return false;
    if (!aes.decrypt(ciphertext, decrypted, tag)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_string_cfb() {
    iar::utils::AES aes;

    aes.set_mode(iar::utils::AESMode::CFB);
    if (!aes.generate_key()) return false;

    std::string plaintext = "This is a test string.";
    std::string ciphertext, tag, decrypted;

    if (!aes.encrypt(plaintext, ciphertext, tag)) return false;
    if (!aes.decrypt(ciphertext, decrypted, tag)) return false;

    //std::cout << "Plaintext: " << plaintext << std::endl;
    //std::cout << "Encrypted: " << ciphertext << std::endl;
    //std::cout << "Decrypted: " << decrypted << std::endl;

    return plaintext == decrypted;
}

bool test_aes_encrypt_decrypt_binary() {
    iar::utils::AES aes;
    if (!aes.generate_key())
        return false;

    std::vector<uint8_t> input = {10, 20, 30, 40, 50};
    std::vector<uint8_t> encrypted, decrypted, tag;

    if (!aes.encrypt(input, encrypted, &tag))
        return false;

    if (!aes.decrypt(encrypted, decrypted, &tag))
        return false;

    return decrypted == input;
}

bool test_aes_encrypt_decrypt_file() {
    iar::utils::AES aes;
    if (!aes.generate_key())
        return false;

    std::string input_text = "Sensitive file contents";
    std::ofstream("aes_input.txt") << input_text;

    if (!aes.encrypt_file("aes_input.txt", "aes_output.enc", "aes_tag.dat"))
        return false;

    if (!aes.decrypt_file("aes_output.enc", "aes_output.txt", "aes_tag.dat"))
        return false;

    std::ifstream decrypted("aes_output.txt");
    std::string result((std::istreambuf_iterator<char>(decrypted)), std::istreambuf_iterator<char>());

    std::remove("aes_input.txt");
    std::remove("aes_output.enc");
    std::remove("aes_output.txt");
    std::remove("aes_tag.dat");

    return result == input_text;
}

bool test_aes_encrypt_decrypt_stream() {
    iar::utils::AES aes;
    if (!aes.generate_key()) return false;

    std::string input_text = "This is stream-based iar::utils::AES encryption test.";
    std::istringstream in_stream(input_text);
    std::ostringstream encrypted_stream, decrypted_stream, tag_stream;

    if (!aes.encrypt_stream(in_stream, encrypted_stream, &tag_stream)) return false;

    std::istringstream encrypted_input(encrypted_stream.str());
    std::istringstream tag_input(tag_stream.str());

    if (!aes.decrypt_stream(encrypted_input, decrypted_stream, &tag_input)) return false;
    return input_text == decrypted_stream.str();
}

bool test_aes_decrypt_tampered_ciphertext_fails() {
    iar::utils::AES aes;
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

