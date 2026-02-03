#pragma once

#include <cstddef>

bool test_default_constructor_resets_all_bits();
bool test_word_constructor_fills_all_words();
bool test_single_bit_set_and_test();
bool test_single_bit_reset();
bool test_single_bit_flip();
bool test_count_empty_and_full();
bool test_count_sparse_pattern();
bool test_multiword_boundary_bits();
bool test_bitwise_or_and_xor();
bool test_bitwise_not_masks_unused_bits();
bool test_row_mask_generation();
bool test_col_mask_generation();
bool test_main_diagonal_mask();
bool test_anti_diagonal_mask();
bool test_square_index_mapping();
bool test_render_bitset_with_square_board();
