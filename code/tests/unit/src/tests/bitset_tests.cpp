
#include <sstream>
#include "bitset_tests.h"
#include "bitset.h"

// ------------------------------------------------------------

bool test_default_constructor_resets_all_bits()
{
    cpp::utils::Bitset<128> b;
    for (size_t i = 0; i < b.NumBits; ++i)
        if (b.test(i)) return false;
    return true;
}

// ------------------------------------------------------------

bool test_word_constructor_fills_all_words()
{
    cpp::utils::Bitset<130> b(~0ULL);
    for (size_t i = 0; i < b.NumBits; ++i)
        if (!b.test(i)) return false;
    return true;
}

// ------------------------------------------------------------

bool test_single_bit_set_and_test()
{
    cpp::utils::Bitset<64> b;
    b.set(13);
    return b.test(13) && b.count() == 1;
}

// ------------------------------------------------------------

bool test_single_bit_reset()
{
    cpp::utils::Bitset<64> b;
    b.set(7);
    b.reset(7);
    return !b.test(7) && b.count() == 0;
}

// ------------------------------------------------------------

bool test_single_bit_flip()
{
    cpp::utils::Bitset<64> b;
    b.flip(5);
    if (!b.test(5)) return false;
    b.flip(5);
    return !b.test(5);
}

// ------------------------------------------------------------

bool test_count_empty_and_full()
{
    cpp::utils::Bitset<100> a;
    if (a.count() != 0) return false;

    for (size_t i = 0; i < a.NumBits; ++i)
        a.set(i);

    return a.count() == a.NumBits;
}

// ------------------------------------------------------------

bool test_count_sparse_pattern()
{
    cpp::utils::Bitset<128> b;
    for (size_t i = 0; i < 128; i += 3)
        b.set(i);

    return b.count() == (128 + 2) / 3;
}

// ------------------------------------------------------------

bool test_multiword_boundary_bits()
{
    cpp::utils::Bitset<130> b;
    b.set(63);
    b.set(64);
    b.set(129);

    return b.test(63) && b.test(64) && b.test(129) && b.count() == 3;
}

// ------------------------------------------------------------

bool test_bitwise_or_and_xor()
{
    cpp::utils::Bitset<64> a, b;

    a.set(1);
    a.set(3);
    b.set(3);
    b.set(4);

    cpp::utils::Bitset<64> c = a | b;
    if (!(c.test(1) && c.test(3) && c.test(4))) return false;

    cpp::utils::Bitset<64> d = a & b;
    if (!(d.count() == 1 && d.test(3))) return false;

    cpp::utils::Bitset<64> e = a ^ b;
    return e.count() == 2 && e.test(1) && e.test(4);
}

// ------------------------------------------------------------

bool test_bitwise_not_masks_unused_bits()
{
    cpp::utils::Bitset<70> b;
    for (size_t i = 0; i < 70; ++i)
        b.set(i);

    auto c = ~b;
    for (size_t i = 0; i < 70; ++i)
        if (c.test(i)) return false;

    return true;
}

// ------------------------------------------------------------

bool test_row_mask_generation()
{
    constexpr size_t W = 4, H = 3;
    auto mask = cpp::utils::Bitset<W*H>::template row_mask<W, H>(1);

    size_t count = 0;
    for (size_t col = 0; col < W; ++col)
        if (mask.test(1 * W + col)) ++count;

    return count == W;
}

// ------------------------------------------------------------

bool test_col_mask_generation()
{
    constexpr size_t W = 4, H = 3;
    auto mask = cpp::utils::Bitset<W*H>::template col_mask<W, H>(2);

    size_t count = 0;
    for (size_t row = 0; row < H; ++row)
        if (mask.test(row * W + 2)) ++count;

    return count == H;
}

// ------------------------------------------------------------

bool test_main_diagonal_mask()
{
    constexpr size_t W = 4, H = 4;
    auto mask = cpp::utils::Bitset<W*H>::template main_diag_mask<W, H>(0, 0);

    return mask.count() == 4 &&
           mask.test(0) &&
           mask.test(5) &&
           mask.test(10) &&
           mask.test(15);
}

// ------------------------------------------------------------

bool test_anti_diagonal_mask()
{
    constexpr size_t W = 4, H = 4;
    auto mask = cpp::utils::Bitset<W*H>::template anti_diag_mask<W, H>(0, 3);

    return mask.count() == 4 &&
           mask.test(3) &&
           mask.test(6) &&
           mask.test(9) &&
           mask.test(12);
}

// ------------------------------------------------------------

bool test_square_index_mapping()
{
    return cpp::utils::Bitset<1>::square_index(2, 3, 8) == 19;
}

// ------------------------------------------------------------

bool test_render_bitset_with_square_board()
{
    constexpr size_t W = 3, H = 2;
    cpp::utils::Bitset<W*H> b;
    b.set(0);
    b.set(4);

    cpp::utils::SquareBoard board(W, H);

    std::ostringstream os;
    std::vector<bool> bits(W*H);
    for (size_t i = 0; i < W*H; ++i)
        bits[i] = b.test(i);

    board.render(bits, os);

    const std::string expected =
        "010\n"
        "100\n";

    return os.str() == expected;
}