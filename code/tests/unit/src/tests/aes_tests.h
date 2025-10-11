#pragma once

bool test_aes_key_generation_export_import();

bool test_aes_encrypt_decrypt_string_gcm();
bool test_aes_encrypt_decrypt_string_cbc();
bool test_aes_encrypt_decrypt_string_ecb();
bool test_aes_encrypt_decrypt_string_cfb();

bool test_aes_encrypt_decrypt_binary();

bool test_aes_encrypt_decrypt_file();

bool test_aes_encrypt_decrypt_stream();

bool test_aes_decrypt_tampered_ciphertext_fails();

