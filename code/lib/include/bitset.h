
#pragma once
#include <array>
#include <cstdint>
#include <iostream>
#include <cassert>
#include <string>
#include <vector>

namespace iar { namespace utils {

    // User-defined constants
    constexpr int uint64_bytesize = sizeof(uint64_t);
    constexpr int uint64_bitsize  = sizeof(unsigned char) * uint64_bytesize;
    // Typically 64 bits on modern systems

    // =====================================
    // Small utilities
    // =====================================
    inline constexpr uint64_t bitmask64(int bit) {
        return (bit < uint64_bitsize) ? (uint64_t(1) << bit) : 0ULL;
    }
    inline constexpr int word_index(size_t i) { return int(i >> (uint64_bytesize - 2)); }      // i / 64
    inline constexpr int bit_index(size_t i)  { return int(i & (uint64_bitsize - 1)); }      // i % 64

    // General-purpose bitset for arbitrary board sizes (N cells)
    template <size_t N>
    class Bitset {
    public:
        static constexpr size_t NumBits  = N;
        static constexpr size_t BitsPerWord = size_t(uint64_bitsize);
        static constexpr size_t NumWords = (N + uint64_bitsize - 1) / uint64_bitsize;
        using Word = uint64_t;

    private:
        std::array<Word, NumWords> data{};

    public:
        Bitset() { reset(); }
        Bitset(Word word) { data.fill(word); }

        // --- Clear all bits ---
        void reset() { data.fill(0ULL); }

        // --- Single-bit operations ---
        bool test(size_t bit) const {
            assert(bit < NumBits);
            return (data[bit / uint64_bitsize] >> (bit % uint64_bitsize)) & 1ULL;
        }
        void set(size_t bit) {
            assert(bit < NumBits);
            data[bit / uint64_bitsize] |= (Word(1) << (bit % uint64_bitsize));
        }
        void reset(size_t bit) {
            assert(bit < NumBits);
            data[bit / uint64_bitsize] &= ~(Word(1) << (bit % uint64_bitsize));
        }
        void flip(size_t bit) {
            assert(bit < NumBits);
            data[bit / uint64_bitsize] ^= (Word(1) << (bit % uint64_bitsize));
        }

        // population count
        size_t count() const {
            size_t c = 0;
    #if defined(__GNUG__) || defined(__clang__)
            for (size_t i = 0; i < NumWords; ++i) c += __builtin_popcountll(data[i]);
    #else
            for (size_t i = 0; i < NumWords; ++i) {
                Word w = data[i];
                while (w) { w &= (w - 1); ++c; }
            }
    #endif
            return c;
        }

        // --- Overlay support (bitwise ops) ---
        Bitset& operator|=(const Bitset& other) {
            for (size_t i = 0; i < NumWords; i++) data[i] |= other.data[i];
            return *this;
        }
        Bitset& operator&=(const Bitset& other) {
            for (size_t i = 0; i < NumWords; i++) data[i] &= other.data[i];
            return *this;
        }
        Bitset& operator^=(const Bitset& other) {
            for (size_t i = 0; i < NumWords; i++) data[i] ^= other.data[i];
            return *this;
        }

        // bitwise NOT (operator~) — respects the valid bit count and clears high unused bits
        Bitset operator~() const {
            Bitset r;
            for (size_t i = 0; i < NumWords; ++i) r.data[i] = ~data[i];

            const size_t rem = NumBits % BitsPerWord;
            if (rem != 0) {
                // mask to keep only valid low `rem` bits in last word
                const Word mask = ( (Word(1) << rem) - Word(1) );
                r.data.back() &= mask;
            }
            return r;
        }

        friend Bitset operator|(Bitset a, const Bitset& b) { return a |= b; }
        friend Bitset operator&(Bitset a, const Bitset& b) { return a &= b; }
        friend Bitset operator^(Bitset a, const Bitset& b) { return a ^= b; }

        bool any()
        {
            auto content = 0;
            for(auto& mask : data)
            {
                content |= mask;
            }
            return content != 0;
        }

        // --- Utility: set entire row ---
        template <size_t W, size_t H>
        static Bitset<W*H> row_mask(size_t row) {
            Bitset<W*H> mask;
            for (size_t col = 0; col < W; ++col)
                mask.set(square_index(row, col, W));
            return mask;
        }

        // --- Utility: set entire column ---
        template <size_t W, size_t H>
        static Bitset<W*H> col_mask(size_t col) {
            Bitset<W*H> mask;
            for (size_t row = 0; row < H; ++row)
                mask.set(square_index(row, col, W));
            return mask;
        }

        // --- Utility: set diagonal (↘ main, ↙ anti) ---
        template <size_t W, size_t H>
        static Bitset<W*H> main_diag_mask(int r0, int c0) {
            Bitset<W*H> mask;
            int r = r0, c = c0;
            while (r < (int)H && c < (int)W) {
                mask.set(square_index(r, c, W));
                r++; c++;
            }
            return mask;
        }
        template <size_t W, size_t H>
        static Bitset<W*H> anti_diag_mask(int r0, int c0) {
            Bitset<W*H> mask;
            int r = r0, c = c0;
            while (r < (int)H && c >= 0) {
                mask.set(square_index(r, c, W));
                r++; c--;
            }
            return mask;
        }

        // --- Debug/Render (square board only) ---
        template <size_t W, size_t H>
        void render() const {
            static_assert(W*H == NumBits, "Board dimensions mismatch");
            for (int row = int(H)-1; row >= 0; --row) {
                for (size_t col = 0; col < W; ++col) {
                    size_t idx = square_index(row, col, W);
                    std::cout << (test(idx) ? "1 " : "0 ");
                }
                std::cout << "\n";
            }
        }

        // --- (row, col) → linear index mapping ---
        static size_t square_index(size_t row, size_t col, size_t W) {
            return row * W + col;
        }
    };



    struct RenderOptions {
        char empty = '0';
        char filled = '1';
    };

    // Abstract base
    class BoardShape {
    public:
        virtual ~BoardShape() = default;
        virtual size_t num_cells() const = 0;
        virtual void render(const std::vector<bool>& bits, std::ostream& os, const RenderOptions& opts = {}) const = 0;
    };

    class SquareBoard : public BoardShape {
        size_t W, H;
    public:
        SquareBoard(size_t w, size_t h) : W(w), H(h) {}
        size_t num_cells() const override { return W*H; }

        void render(const std::vector<bool>& bits, std::ostream& os, const RenderOptions& opts = {}) const override
        {
            for (int row = int(H)-1; row >= 0; --row) {
                for (size_t col = 0; col < W; ++col) {
                    size_t idx = row*W + col;
                    os << (bits[idx] ? opts.filled : opts.empty);
                }
                os << "\n";
            }
        }
    };

    /*
    class TriangularBoard : public BoardShape {
        size_t N; // side length
    public:
        TriangularBoard(size_t n) : N(n) {}
        size_t num_cells() const override { return N*(N+1)/2; }

        void render(const std::vector<bool>& bits,
                    std::ostream& os,
                    const RenderOptions& opts = {}) const override {
            size_t idx = 0;
            for (int row = int(N)-1; row >= 0; --row) {
                // padding for triangle shape
                for (int pad=0; pad < (int(N)-1-row); ++pad) os << ' ';
                for (size_t col = 0; col <= row; ++col) {
                    os << (bits[idx++] ? opts.filled : opts.empty) << ' ';
                }
                os << "\n";
            }
        }
    };

    class HexBoard : public BoardShape {
        size_t R;
    public:
        HexBoard(size_t r) : R(r) {}
        size_t num_cells() const override { return 3*R*(R-1)+1; }

        void render(const std::vector<bool>& bits,
                    std::ostream& os,
                    const RenderOptions& opts = {}) const override {
            size_t idx=0;
            // rows from -(R-1) to +(R-1)
            for (int q = -int(R-1); q <= int(R-1); ++q) {
                int minr = std::max(-int(R-1), -q-int(R-1));
                int maxr = std::min(int(R-1), -q+int(R-1));
                for (int pad=0; pad < (int(R-1)-maxr); ++pad) os << ' ';
                for (int r = minr; r <= maxr; ++r) {
                    os << (bits[idx++] ? opts.filled : opts.empty) << ' ';
                }
                os << "\n";
            }
        }
    };
    */

    template <size_t N>
    void render_bitset(const Bitset<N>& bset, const BoardShape& shape) {
        std::vector<bool> bits(N);
        for (size_t i=0; i<N; ++i) bits[i] = bset.test(i);
        shape.render(bits, std::cout);
    }




} }