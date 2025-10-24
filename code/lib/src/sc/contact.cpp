
#include "sc/contact.h"
#include "file.h"
#include "zip_file.h"

bool iar::utils::SCContact::autoGenerateKeys()
{
    auto success = _rsaKeyPair.generate_keypair() &&
        //_aesKey.generate_key()  &&
        _eccKeyPair.generate_own_keypair();
    
    return success;
}



Json::Value iar::utils::SCContact::exportContact()
{
    miniz_cpp::zip_file file;
    mz_zip_archive archive;

    std::string rsaPublic, rsaPrivate;
    std::string eccPublic, eccPrivate;
    std::string aesKeyStr;

    rsaKey().public_key(rsaPublic);
    rsaKey().private_key(rsaPrivate);
    eccKey().get_own_public_key_pem(eccPublic);
    eccKey().get_own_private_key_pem(eccPrivate);

    std::stringstream ss;
    ss << aesKey().hex_encoded_key() << ":" << aesKey().hex_encoded_iv();

    file.writestr("keys/rsa.public.pem", rsaPublic);
    file.writestr("keys/rsa.private.pem", rsaPrivate);
    file.writestr("keys/ecc.public.pem", eccPublic);
    file.writestr("keys/ecc.private.pem", eccPrivate);
    file.writestr("keys/aes.key", ss.str());

    ss.str("");
    ss.clear();

    ss << Name() << ".zip";
    file.save(ss.str());

    Json::Value obj;
    obj["name"] = Name();

    return obj;
}

bool iar::utils::SCContact::importContact(const Json::Value& value)
{
    auto success = false;

    return success;
}