#pragma once

#include "aes.h"
#include "ecc.h"
#include "des3.h"
#include "rsa.h"

#include <string>
#include <json/json.h>
#include "uuid.h"

namespace iar { namespace utils {

    class SCContact
    {
        public:

            SCContact(): _name(generate_uuid()) {}
            SCContact(const std::string& name): _name(name) {}

            ////////////////////////////////////////////////////
            // Getters / Setters
            ////////////////////////////////////////////////////

            const std::string& Name() { return _name; }
            void Name(const std::string& name) { _name = name; }

            AES& aesKey() { return _aesKey; }
            //DES3& des3Key() { return _desKey; }
            ECC& eccKey() { return _eccKeyPair; }
            RSA& rsaKey() { return _rsaKeyPair; }


            ////////////////////////////////////////////////////
            // Overloaded Operators
            ////////////////////////////////////////////////////

            SCContact& operator=(const SCContact& other)
            {
                if (this != &other) {
                    // TODO
                }
                return *this;
            }

            bool operator==(const SCContact& other) const {
                return _name.compare(other._name) == 0;
            }

            ////////////////////////////////////////////////////
            // Public Methods
            ////////////////////////////////////////////////////

            bool autoGenerateKeys();

            Json::Value exportContact();
            bool importContact(const Json::Value& value);
            

        private:
            std::string _name;
            RSA _rsaKeyPair;
            ECC _eccKeyPair;
            AES _aesKey;
            //DES3 _desKey;
    };

}}