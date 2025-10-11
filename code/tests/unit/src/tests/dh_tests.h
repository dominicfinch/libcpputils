#pragma once

bool test_generate_parameters();
bool test_generate_keypair();
bool test_get_set_parameters();
bool test_public_key_string_export();
bool test_public_key_binary_export();
bool test_set_peer_public_key_and_compute_shared_secret();
bool test_clear_keypair_resets_state();

bool test_public_key_without_keypair();
bool test_set_invalid_peer_key();
bool test_compute_secret_without_peer_key();
bool test_compute_secret_without_keypair();
