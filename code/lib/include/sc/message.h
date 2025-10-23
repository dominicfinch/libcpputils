
#pragma once

#include <vector>
#include <cstdint>
#include <string>


namespace iar { namespace utils {

    class SCMessage {
        public:

            uint64_t Id() { return _id; }

            std::vector<uint8_t>& Content() { return _content; }
            std::vector<uint8_t>& Signature() { return _signature; }

        private:
            std::vector<uint8_t> _content;
            std::vector<uint8_t> _signature;
            uint64_t _timestamp;

            uint64_t _id = 0;
            uint64_t _maxContentSize = 1 << 10;
            unsigned char _apiVersion = 0x00;
            std::string _hash_algo = "sha384";
    };



    // TODO
    /*
    class SCChunkMessage: public SCMessage {
        public:

            std::vector<SCMessage>& chunks() { return _chunks; }

        private:
            std::vector<SCMessage> _chunks;
    };


    class SCFileMessage: public SCChunkMessage {

    };
    */
    
}}
