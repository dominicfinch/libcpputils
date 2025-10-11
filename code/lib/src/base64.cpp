
#include "base64.h"

#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>

namespace iar { namespace utils {

    bool Base64::encode(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new(BIO_s_mem());
        if (!b64 || !mem) return false;

        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        b64 = BIO_push(b64, mem);

        if (BIO_write(b64, input.data(), input.size()) <= 0) {
            BIO_free_all(b64);
            return false;
        }

        if (BIO_flush(b64) != 1) {
            BIO_free_all(b64);
            return false;
        }

        BUF_MEM* buffer_ptr;
        BIO_get_mem_ptr(b64, &buffer_ptr);

        output.assign(buffer_ptr->data, buffer_ptr->data + buffer_ptr->length);
        BIO_free_all(b64);
        return true;
    }

    // Decode Base64 (vector) to binary (vector)
    bool Base64::decode(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new_mem_buf(input.data(), input.size());
        if (!b64 || !mem) return false;

        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        mem = BIO_push(b64, mem);

        std::vector<uint8_t> buffer(input.size());  // Max decoded size <= encoded size
        int len = BIO_read(mem, buffer.data(), buffer.size());
        if (len <= 0) {
            BIO_free_all(mem);
            return false;
        }

        output.assign(buffer.begin(), buffer.begin() + len);
        BIO_free_all(mem);
        return true;
    }

    // Encode string to Base64 string
    bool Base64::encode(const std::string& input, std::string& output) {
        std::vector<uint8_t> input_bytes(input.begin(), input.end());
        std::vector<uint8_t> output_bytes;
        if (!encode(input_bytes, output_bytes))
            return false;
        output.assign(output_bytes.begin(), output_bytes.end());
        return true;
    }

    // Decode Base64 string to string
    bool Base64::decode(const std::string& input, std::string& output) {
        std::vector<uint8_t> input_bytes(input.begin(), input.end());
        std::vector<uint8_t> output_bytes;
        if (!decode(input_bytes, output_bytes))
            return false;
        output.assign(output_bytes.begin(), output_bytes.end());
        return true;
    }

    std::string Base64::encode(const std::vector<uint8_t>& input)
    {
        std::vector<uint8_t> output;
        encode(input, output);
        return std::string(output.begin(), output.end());
    }

    std::vector<uint8_t> Base64::decode(const std::string& input)
    {
        std::vector<uint8_t> output_vect;
        std::vector<uint8_t> input_vect(input.begin(), input.end());
        decode(input_vect, output_vect);
        return output_vect;
    }
}}
