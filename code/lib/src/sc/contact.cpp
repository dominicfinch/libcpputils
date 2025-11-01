
#include "sc/contact.h"
#include "base64.h"
#include "file.h"
#include "zip_file.h"

bool iar::utils::SCContact::autoGenerateKeys()
{
    auto success = _eccKeyPair.generate_own_keypair();
    return success;
}



Json::Value iar::utils::SCContact::toJSON(bool full)
{
    std::string eccPublic, eccPrivate;

    eccKey().get_own_public_key_pem(eccPublic);
    eccKey().get_own_private_key_pem(eccPrivate);

    std::vector<uint8_t> pubKeyVect(eccPublic.begin(), eccPublic.end());
    std::vector<uint8_t> privKeyVect(eccPrivate.begin(), eccPrivate.end());

    Json::Value obj;
    obj["name"] = Name();
    obj["ecc.public"] = iar::utils::Base64::encode(pubKeyVect);

    if(full) {
        obj["ecc.private"] = iar::utils::Base64::encode(privKeyVect);
    }

    return obj;
}

bool iar::utils::SCContact::fromJSON(const Json::Value& value)
{
    _name = value["name"].asString();   
    _eccKeyPair.clear_keypair();
    auto decodedPublicKey = iar::utils::Base64::decode(value["ecc.public"].asString());
    auto decodedPrivateKey = iar::utils::Base64::decode(value["ecc.private"].asString());

    _eccKeyPair.load_own_public_key_from_pem((const char *)decodedPublicKey.data());
    _eccKeyPair.load_own_private_key_from_pem((const char *)decodedPrivateKey.data());
    return true;
}


bool iar::utils::SCContact::toZIPFile(const std::string& fpath, bool full)
{
    
    return false;
}

bool iar::utils::SCContact::toZIPData(std::string& content, bool full)
{

    return false;
}

bool iar::utils::SCContact::fromZIPFile(const std::string& fpath)
{
    auto success = false;
    //mz_zip_archive archive;




    return success;
}

bool iar::utils::SCContact::fromZIPData(std::string& content)
{
    auto success = false;

    return success;
}