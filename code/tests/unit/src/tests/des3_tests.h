
#pragma once

#include <cstdint>
#include <vector>

std::vector<uint8_t> random_bytes(size_t length);

bool test_des3_cbc_encrypt_decrypt();
bool test_des3_cbc_invalid_key_size();
bool test_des3_cbc_invalid_iv_size();

bool test_des3_ecb_encrypt_decrypt();
bool test_des3_ecb_reject_iv();

bool test_des3_encrypt_without_key();
bool test_des3_decrypt_without_key();
bool test_des3_clear_resets_state();