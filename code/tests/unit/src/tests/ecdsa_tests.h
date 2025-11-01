#pragma once

bool test_ecdsa_generate_keypair_and_export_import();
bool test_ecdsa_sign_and_verify_sha384();
bool test_ecdsa_sign_and_verify_sha512();
bool test_ecdsa_import_invalid_key();
bool test_ecdsa_export_without_key();
bool test_ecdsa_verify_fails_on_wrong_signature();
bool test_ecdsa_generate_invalid_bits();
