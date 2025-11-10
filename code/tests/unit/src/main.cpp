
#include <iostream>
#include "test_sets.h"
#include <openssl/provider.h>

void print_test_results(const std::map<std::string, iar::test_set_results>& results);


void print_test_results(const std::map<std::string, iar::test_set_results>& results)
{
    std::cout << "\nOverall Results:\n";
    int total_passed = 0, total_failed = 0, total_tests = 0;
    for(auto ts : results)
    {
        total_passed += ts.second.tests_passed;
        total_failed += ts.second.tests_failed;
        total_tests += ts.second.test_set_count;
        std::cout << " - " << ts.first << ": " << ts.second.tests_passed << "/" << ts.second.test_set_count << std::endl;
    }

    std::cout << "\nTotal Executed: " << total_tests << std::endl;
    std::cout << "Total Passed: " << total_passed << std::endl;
    std::cout << "Total Failed: " << total_failed << std::endl;
}

int main()
{
    iar::TestRunner testRunner;

    testRunner.add_test_set("aes_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning AES tests...\n";
        runner->execute_test(results, "test_aes_key_generation_export_import", test_aes_key_generation_export_import);
        runner->execute_test(results, "test_aes_encrypt_decrypt_string_gcm", test_aes_encrypt_decrypt_string_gcm);
        runner->execute_test(results, "test_aes_encrypt_decrypt_string_cbc", test_aes_encrypt_decrypt_string_cbc);
        runner->execute_test(results, "test_aes_encrypt_decrypt_string_cfb", test_aes_encrypt_decrypt_string_cfb);
        runner->execute_test(results, "test_aes_encrypt_decrypt_string_ecb", test_aes_encrypt_decrypt_string_ecb);
        runner->execute_test(results, "test_aes_encrypt_decrypt_binary", test_aes_encrypt_decrypt_binary);
        runner->execute_test(results, "test_aes_encrypt_decrypt_file", test_aes_encrypt_decrypt_file);
        runner->execute_test(results, "test_aes_encrypt_decrypt_stream", test_aes_encrypt_decrypt_stream);
        runner->execute_test(results, "test_aes_decrypt_tampered_ciphertext_fails", test_aes_decrypt_tampered_ciphertext_fails);
    });

    testRunner.add_test_set("bchain_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning BCHAIN tests...\n";
        runner->execute_test(results, "test_blockchain_serialize_roundtrip", test_blockchain_serialize_roundtrip);
        runner->execute_test(results, "test_blockchain_save_load_jsoncpp", test_blockchain_save_load_jsoncpp);
    });

    testRunner.add_test_set("btree_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning BTREE tests...\n";
        runner->execute_test(results, "test_insert_and_contains", test_insert_and_contains);
        runner->execute_test(results, "test_insert_duplicates", test_insert_duplicates);
        runner->execute_test(results, "test_in_order_traversal_sorted", test_in_order_traversal_sorted);
        runner->execute_test(results, "test_remove_leaf_node", test_remove_leaf_node);
        runner->execute_test(results, "test_remove_node_with_one_child", test_remove_node_with_one_child);
        runner->execute_test(results, "test_remove_node_with_two_children", test_remove_node_with_two_children);
        runner->execute_test(results, "test_remove_root_node", test_remove_root_node);
        runner->execute_test(results, "test_clear_tree", test_clear_tree);
        runner->execute_test(results, "test_empty_tree", test_empty_tree);
        runner->execute_test(results, "test_remove_nonexistent_node", test_remove_nonexistent_node);
        runner->execute_test(results, "test_string_payloads", test_string_payloads);
        runner->execute_test(results, "test_mutable_search", test_mutable_search);
        runner->execute_test(results, "test_custom_comparator", test_custom_comparator);
        runner->execute_test(results, "test_search_found_and_not_found", test_search_found_and_not_found);
    });

    testRunner.add_test_set("b58_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning Base58 tests...\n";
        runner->execute_test(results, "test_base58_encode_decode", test_base58_encode_decode);
    });

    testRunner.add_test_set("b64_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning Base64 tests...\n";
        runner->execute_test(results, "test_base64_encode_decode", test_base64_encode_decode);
    });

#ifndef EXCLUDE_CERT_TESTS
    testRunner.add_test_set("certificate_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning Certificate tests...\n";
        runner->execute_test(results, "test_certificatebuilder_set_subject", test_certificatebuilder_set_subject);
        runner->execute_test(results, "test_certificatebuilder_set_validity_days", test_certificatebuilder_set_validity_days);
        runner->execute_test(results, "test_certificatebuilder_set_serial_number", test_certificatebuilder_set_serial_number);
        runner->execute_test(results, "test_certificatebuilder_set_public_key_from_rsa", test_certificatebuilder_set_public_key_from_rsa);
        runner->execute_test(results, "test_certificatebuilder_set_public_key_from_ecc", test_certificatebuilder_set_public_key_from_ecc);
        runner->execute_test(results, "test_certificatebuilder_self_sign_with_rsa", test_certificatebuilder_self_sign_with_rsa);
        runner->execute_test(results, "test_certificatebuilder_self_sign_with_ecc", test_certificatebuilder_self_sign_with_ecc);
        runner->execute_test(results, "test_certificatebuilder_sign_with_ca_rsa", test_certificatebuilder_sign_with_ca_rsa);
        runner->execute_test(results, "test_certificatebuilder_sign_with_ca_ecc", test_certificatebuilder_sign_with_ca_ecc);
        runner->execute_test(results, "test_certificatebuilder_save_pem", test_certificatebuilder_save_pem);
        runner->execute_test(results, "test_certificatebuilder_save_der", test_certificatebuilder_save_der);
        runner->execute_test(results, "test_certificatebuilder_get_certificate_pem", test_certificatebuilder_get_certificate_pem);
        runner->execute_test(results, "test_certificatebuilder_get_certificate_der", test_certificatebuilder_get_certificate_der);
        runner->execute_test(results, "test_certificatebuilder_export_to_pkcs12", test_certificatebuilder_export_to_pkcs12);

        runner->execute_test(results, "test_load_from_pem", test_load_from_pem);
        runner->execute_test(results, "test_load_from_pem_file", test_load_from_pem_file);
        runner->execute_test(results, "test_load_from_der_file", test_load_from_der_file);
        runner->execute_test(results, "test_get_common_name", test_get_common_name);
        runner->execute_test(results, "test_verify_signature_self_signed", test_verify_signature_self_signed);
    });
#endif

    testRunner.add_test_set("des3_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning DES3 tests...\n";
        runner->execute_test(results, "test_des3_cbc_encrypt_decrypt", test_des3_cbc_encrypt_decrypt);
        runner->execute_test(results, "test_des3_cbc_invalid_key_size", test_des3_cbc_invalid_key_size);
        runner->execute_test(results, "test_des3_cbc_invalid_iv_size", test_des3_cbc_invalid_iv_size);
        runner->execute_test(results, "test_des3_ecb_encrypt_decrypt", test_des3_ecb_encrypt_decrypt);
        runner->execute_test(results, "test_des3_ecb_reject_iv", test_des3_ecb_reject_iv);
        runner->execute_test(results, "test_des3_encrypt_without_key", test_des3_encrypt_without_key);
        runner->execute_test(results, "test_des3_decrypt_without_key", test_des3_decrypt_without_key);
        runner->execute_test(results, "test_des3_clear_resets_state", test_des3_clear_resets_state);
    });

#ifndef EXCLUDE_DH_TESTS
    testRunner.add_test_set("dh_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning DH tests...\n";
        runner->execute_test(results, "test_generate_parameters", test_generate_parameters);
        runner->execute_test(results, "test_generate_keypair", test_generate_keypair);
        runner->execute_test(results, "test_get_set_parameters", test_get_set_parameters);
        runner->execute_test(results, "test_public_key_string_export", test_public_key_string_export);
        runner->execute_test(results, "test_public_key_binary_export", test_public_key_binary_export);
        runner->execute_test(results, "test_set_peer_public_key_and_compute_shared_secret", test_set_peer_public_key_and_compute_shared_secret);
        runner->execute_test(results, "test_clear_keypair_resets_state", test_clear_keypair_resets_state);
        runner->execute_test(results, "test_public_key_without_keypair", test_public_key_without_keypair);
        runner->execute_test(results, "test_set_invalid_peer_key", test_set_invalid_peer_key);
        runner->execute_test(results, "test_compute_secret_without_peer_key", test_compute_secret_without_peer_key);
        runner->execute_test(results, "test_compute_secret_without_keypair", test_compute_secret_without_keypair);
    });
#endif
    
    testRunner.add_test_set("ecc_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning ECC tests...\n";
        runner->execute_test(results, "test_key_generation_and_export_import", test_key_generation_and_export_import);
        runner->execute_test(results, "test_shared_secret_derivation", test_shared_secret_derivation);
        runner->execute_test(results, "test_signing_and_verification", test_signing_and_verification);
        runner->execute_test(results, "test_encryption_decryption_binary", test_encryption_decryption_binary);
        runner->execute_test(results, "test_encryption_decryption_strings", test_encryption_decryption_strings);
        runner->execute_test(results, "test_ecc_load_own_public_key_from_pem", test_ecc_load_own_public_key_from_pem);
        runner->execute_test(results, "test_ecc_load_own_private_key_from_pem", test_ecc_load_own_private_key_from_pem);
    });

    testRunner.add_test_set("ed25519_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning ED25519 tests...\n";
        runner->execute_test(results, "test_ed25519_generate_keypair", test_ed25519_generate_keypair);
        runner->execute_test(results, "test_ed25519_export_import_private_key", test_ed25519_export_import_private_key);
        runner->execute_test(results, "test_ed25519_export_import_public_key", test_ed25519_export_import_public_key);
        runner->execute_test(results, "test_ed25519_encrypt_decrypt_vector", test_ed25519_encrypt_decrypt_vector);
        runner->execute_test(results, "test_ed25519_encrypt_decrypt_string", test_ed25519_encrypt_decrypt_string);
        runner->execute_test(results, "test_ed25519_sign_verify_vector", test_ed25519_sign_verify_vector);
        runner->execute_test(results, "test_ed25519_sign_verify_string", test_ed25519_sign_verify_string);
        runner->execute_test(results, "test_ed25519_sign_verify_roundtrip", test_ed25519_sign_verify_roundtrip);
        runner->execute_test(results, "test_ed25519_private_key_pem_roundtrip", test_ed25519_private_key_pem_roundtrip);
        runner->execute_test(results, "test_ed25519_public_key_pem_roundtrip", test_ed25519_public_key_pem_roundtrip);
        runner->execute_test(results, "test_ed25519_set_private_key_pem_invalid", test_ed25519_set_private_key_pem_invalid);
        runner->execute_test(results, "test_ed25519_set_public_key_pem_invalid", test_ed25519_set_public_key_pem_invalid);
    });

    testRunner.add_test_set("hash_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning HASH tests...\n";
        runner->execute_test(results, "test_hash_md5", test_hash_md5);
        runner->execute_test(results, "test_hash_sha256", test_hash_sha256);
        runner->execute_test(results, "test_hash_sha384", test_hash_sha384);
        runner->execute_test(results, "test_hash_sha512", test_hash_sha512);
    });

    testRunner.add_test_set("hex_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning HEX tests...\n";
        runner->execute_test(results, "test_hex_encode_decode", test_hex_encode_decode);
    });

    testRunner.add_test_set("llist_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning LLIST tests...\n";
        runner->execute_test(results, "test_append_and_size", test_append_and_size);
        runner->execute_test(results, "test_prepend_and_order", test_prepend_and_order);
        runner->execute_test(results, "test_remove_existing_element", test_remove_existing_element);
        runner->execute_test(results, "test_remove_nonexistent_element", test_remove_nonexistent_element);
        runner->execute_test(results, "test_clear_list", test_clear_list);
        runner->execute_test(results, "test_for_each_accumulates_values", test_for_each_accumulates_values);
        runner->execute_test(results, "test_append_after_clear", test_append_after_clear);
    });

    testRunner.add_test_set("rsa_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning RSA tests...\n";
        runner->execute_test(results, "test_rsa_key_copy", test_rsa_key_copy);
        runner->execute_test(results, "test_rsa_generate_keypair", test_rsa_generate_keypair);
        runner->execute_test(results, "test_rsa_encrypt_decrypt", test_rsa_encrypt_decrypt);
        runner->execute_test(results, "test_rsa_export_import_public_key", test_rsa_export_import_public_key);
        runner->execute_test(results, "test_rsa_export_import_private_key", test_rsa_export_import_private_key);
        runner->execute_test(results, "test_rsa_fail_on_invalid_key", test_rsa_fail_on_invalid_key);
        runner->execute_test(results, "test_rsa_sign_verify_success", test_rsa_sign_verify_success);
        runner->execute_test(results, "test_rsa_sign_verify_tampered_message", test_rsa_sign_verify_tampered_message);
        runner->execute_test(results, "test_rsa_sign_verify_tampered_signature", test_rsa_sign_verify_tampered_signature);
        runner->execute_test(results, "test_rsa_sign_invalid_algorithm", test_rsa_sign_invalid_algorithm);
        runner->execute_test(results, "test_rsa_verify_invalid_algorithm", test_rsa_verify_invalid_algorithm);
    });

    testRunner.add_test_set("sc_contact_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning SCContact tests...\n";
        // TODO
    });
    
    testRunner.add_test_set("sc_transceiver_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning SCTransceiver tests...\n";
        runner->execute_test(results, "test_open_channel", test_open_channel);
        runner->execute_test(results, "test_close_channel", test_close_channel);
        runner->execute_test(results, "test_open_channel_send_receive_reply", test_open_channel_send_receive);
        runner->execute_test(results, "test_open_channel_send_receive_long_message", test_open_channel_send_receive_long_message);
    });

    testRunner.add_test_set("wallet_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning Wallet tests...\n";
        runner->execute_test(results, "test_key_generation", test_key_generation);
        runner->execute_test(results, "test_key_extraction", test_key_extraction);
        runner->execute_test(results, "test_key_private_key_import", test_key_private_key_import);
        runner->execute_test(results, "test_key_public_key_export", test_key_public_key_export);
        runner->execute_test(results, "test_wallet_address", test_wallet_address);
        runner->execute_test(results, "test_sign_and_verify_string", test_sign_and_verify_string);
        runner->execute_test(results, "test_sign_and_verify_binary", test_sign_and_verify_binary);
        runner->execute_test(results, "test_encrypt_decrypt_string_prime256v1", test_encrypt_decrypt_string_prime256v1);
        runner->execute_test(results, "test_encrypt_decrypt_string_secp384r1", test_encrypt_decrypt_string_secp384r1);
        runner->execute_test(results, "test_encrypt_decrypt_string_secp521r1", test_encrypt_decrypt_string_secp521r1);
        runner->execute_test(results, "test_encrypt_decrypt_binary", test_encrypt_decrypt_binary);
    });

    testRunner.add_test_set("uuid_tests", [](iar::TestRunner * runner, iar::test_set_results& results) {
        std::cout << "\nRunning UUID tests...\n";
        runner->execute_test(results, "test_uuid_generate", test_uuid_generate);
    });

    std::cout << "Running all unit tests...\n";

    testRunner.run_tests();

    print_test_results(testRunner.results());

    return 0;
}
