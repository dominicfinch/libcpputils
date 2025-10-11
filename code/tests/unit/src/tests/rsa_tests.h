#pragma once

bool test_rsa_generate_keypair();

bool test_rsa_encrypt_decrypt();

bool test_rsa_export_import_public_key();

bool test_rsa_export_import_private_key();

bool test_rsa_fail_on_invalid_key();

bool test_rsa_sign_verify_success();

bool test_rsa_sign_verify_tampered_message();

bool test_rsa_sign_verify_tampered_signature();

bool test_rsa_sign_invalid_algorithm();

bool test_rsa_verify_invalid_algorithm();

bool test_rsa_key_copy();