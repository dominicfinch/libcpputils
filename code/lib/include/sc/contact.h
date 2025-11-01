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

            //AES& aesKey() { return _aesKey; }
            ECC& eccKey() { return _eccKeyPair; }
            //DES3& des3Key() { return _desKey; }
            //RSA& rsaKey() { return _rsaKeyPair; }


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

            Json::Value toJSON(bool full=false);

            bool toZIPFile(const std::string& fpath, bool full=true);
            bool toZIPData(std::string& content, bool full=true);

            bool fromJSON(const Json::Value& value);
            bool fromZIPFile(const std::string& fpath);
            bool fromZIPData(std::string& content);

        private:
            std::string _name;
            ECC _eccKeyPair;
            //AES _aesKey;
            //DES3 _desKey;
            //RSA _rsaKeyPair;
    };

}}