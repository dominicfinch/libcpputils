#pragma once

bool test_ed25519_generate_keypair();
bool test_ed25519_export_import_private_key();
bool test_ed25519_export_import_public_key();
bool test_ed25519_sign_verify_vector();
bool test_ed25519_sign_verify_string();
bool test_ed25519_encrypt_decrypt_vector();
bool test_ed25519_encrypt_decrypt_string();
bool test_ed25519_sign_verify_roundtrip();

bool test_ed25519_private_key_pem_roundtrip();
bool test_ed25519_public_key_pem_roundtrip();
bool test_ed25519_set_private_key_pem_invalid();
bool test_ed25519_set_public_key_pem_invalid();