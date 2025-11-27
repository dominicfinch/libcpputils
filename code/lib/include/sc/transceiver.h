
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
#include "uuid.h"


namespace iar { namespace utils {

    class SCContact {
        public:

            ~SCContact() {
                //_rsaKeyPair.clear_keypair();
                _eccKeyPair.clear_keypair();
                //_aesKey.clear_key();
                _des3Key.clear();
            }

            void RandomInitialize()
            {
                _uid = generate_uuid();
                //_rsaKeyPair.generate_keypair();
                _eccKeyPair.generate_own_keypair();
                //_aesKey.generate_key();
                _des3Key.generate_key();
            }

            const std::string uid()
            {
                return _uid;
            }

            //RSA& rsaKP() { return _rsaKeyPair; }
            ECC& eccKP() { return _eccKeyPair; }
            //AES& aesKey() { return _aesKey; }
            DES3& des3Key() { return _des3Key; }

            SCContact& operator=(const SCContact& other)
            {
                if (this != &other) {
                    _uid = other._uid;
                    // TODO
                }
                return *this;
            }

            bool operator==(const SCContact& other) const {
                return _uid == other._uid;
            }

            Json::Value Export();
            bool Import(const Json::Value& value);


        private:
            std::string _uid;
            //RSA _rsaKeyPair;
            ECC _eccKeyPair;
            //AES _aesKey;
            DES3 _des3Key;
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
            bool exportContact(const std::string& filepath);
            bool importContact(const std::string& filepath);

            void set_debug_pretty_print(bool setting) { _debug_pretty_print = setting; }

        private:
            SCContact _self;
            std::map<std::string, SCContact*> _contacts;
            std::string _hash_algo = "sha384";
            bool _debug_pretty_print = true;
    };


}}