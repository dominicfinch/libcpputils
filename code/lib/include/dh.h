
#pragma once

#include <openssl/evp.h>

#include <vector>
#include <cstdint>
#include <stdexcept>

namespace iar {
    namespace utils {

        class DiffieHellman {
        public:
            DiffieHellman();
            ~DiffieHellman();

            void clear_keypair();

            bool generate_parameters(unsigned int prime_len = 2048);
            bool generate_keypair();

            bool get_parameters(std::vector<uint8_t>& out);
            bool set_parameters(const std::vector<uint8_t>& in);
            
            bool public_key(std::string& key);
            bool public_key(std::vector<uint8_t>& key);

            bool set_peer_public_key(const std::vector<uint8_t>& peer_pubkey);
            bool compute_shared_secret(std::vector<uint8_t>& shared_secret);

        private:
            EVP_PKEY* params = nullptr;
            EVP_PKEY* keypair = nullptr;
            EVP_PKEY* peerkey = nullptr;
        };

    }
}