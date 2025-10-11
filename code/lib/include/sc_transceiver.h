
#pragma once

#include "aes.h"
#include "ecc.h"
#include "des3.h"
#include "rsa.h"
#include "base64.h"
#include "hash.h"
#include "file.h"

#include <vector>
#include <map>
#include <string>
#include <cstdint>
#include <json/json.h>
#include <uuid/uuid.h>


namespace iar { namespace utils {

    class SCContact {
        public:

            ~SCContact() {
                //_rsaKeyPair.clear_keypair();
                _eccKeyPair.clear_keypair();
                //_aesKey.clear_key();
                //_des3Key.clear();
            }

            void RandomInitialize()
            {
                uuid_generate_random(_uid);
                //_rsaKeyPair.generate_keypair();
                _eccKeyPair.generate_own_keypair();
                //_aesKey.generate_key();
                //_des3Key.generate_key();
            }

            const std::string uid()
            {
                char str[37]; // UUID string representation (36 chars + null terminator)
                uuid_unparse(_uid, str);
                return std::string(str);
            }

            //RSA& rsaKP() { return _rsaKeyPair; }
            ECC& eccKP() { return _eccKeyPair; }
            //AES& aesKey() { return _aesKey; }
            //DES3& des3Key() { return _des3Key; }

            SCContact& operator=(const SCContact& other)
            {
                if (this != &other) {
                    uuid_copy(_uid, other._uid);
                }
                return *this;
            }

            bool operator==(const SCContact& other) const {
                return uuid_compare(_uid, other._uid) == 0;
            }

            Json::Value Export();
            bool Import(const Json::Value& value);


        private:
            uuid_t _uid;
            //RSA _rsaKeyPair;
            ECC _eccKeyPair;
            //AES _aesKey;
            //DES3 _des3Key;
    };

    class SCMessageEncryptionStrategy
    {
        public:


        private:

    };

    class SCMessageDecryptionStrategy
    {
        public:


        private:

    };

    class SCMessage {
        public:


        private:
            //std::vector<uint8_t> _publicKey;
            std::vector<uint8_t> _content;
            std::vector<uint8_t> _signature;
            uint64_t _timestamp;

            int _messageId = 0;
            int _maxContentSize = 1 << 10;
            unsigned char _apiVersion = 0x00;
            std::string _hash_algo = "sha384";
    };

    class SCChunkMessage: public SCMessage {
        public:

            

        private:
            std::vector<SCMessage> _chunks;
    };


    class SCFileMessage: public SCChunkMessage {

    };








    

    class SCTransceiver {
        public:

            void RandomInitialize();
            bool OpenChannel(const std::string& name, SCContact * recv);
            bool CloseChannel(const std::string& name);

            //bool EncryptEncodeContent(const std::string& contact, const std::string& input, std::vector<SCMessage>& content);
            //bool DecryptDecodeContent(const std::string& contact, const std::vector<SCMessage>& input, std::string& output);

            //bool EncryptEncodeContent(const std::string& contact, const std::vector<uint8_t>& input, std::vector<SCMessage>& content);
            //bool DecryptDecodeContent(const std::string& contact, const std::vector<SCMessage>& input, std::vector<uint8_t>& output);
            
            bool EncryptEncodeContent(const std::string& contact, const std::string& input, std::string& output);
            bool DecryptDecodeContent(const std::string& contact, const std::string& input, std::string& output);

            bool EncryptEncodeContent(const std::string& contact, const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
            bool DecryptDecodeContent(const std::string& contact, const std::vector<uint8_t>& input, std::vector<uint8_t>& output);

            SCContact * selfContact() { return &_self; }
            void set_debug_pretty_print(bool setting) { _debug_pretty_print = setting; }

        private:
            SCContact _self;
            std::map<std::string, SCContact*> _contacts;
            std::string _hash_algo = "sha384";
            bool _debug_pretty_print = true;
    };


}}