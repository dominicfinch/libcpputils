
#include "sc/transceiver.h"
#include <json/json.h>
#include <iostream>

void iar::utils::SCTransceiver::RandomInitialize()
{
    _self.RandomInitialize();
}

bool iar::utils::SCTransceiver::OpenChannel(const std::string& name, iar::utils::SCContact * recv)
{
    if(recv && _contacts.find(name) == _contacts.end())
    {
        std::string peerPem2;
        _self.eccKP().get_own_public_key_pem(peerPem2);
        recv->eccKP().load_peer_public_key_from_pem(peerPem2);
        _contacts[name] = recv;
        return true;
    }
    return false;
}

bool iar::utils::SCTransceiver::CloseChannel(const std::string& name)
{
    auto contact_it = _contacts.find(name);
    if(contact_it != _contacts.end())
    {
        _contacts.erase(contact_it);
        return true;
    }
    return false;
}

bool iar::utils::SCTransceiver::EncryptEncodeContent(const std::string& contact, const std::vector<uint8_t>& input, std::vector<uint8_t>& output)
{
    auto contact_it = _contacts.find(contact);
    if(contact_it != _contacts.end())
    {
        std::vector<uint8_t> tag, tag_unencoded;
        std::vector<uint8_t> ciphertext, ciphertext_unencoded, ciphertext_finalized;
        std::vector<uint8_t> signature;

        std::vector<uint8_t> iv, iv_encoded;
        std::string peerPem1;

        auto getKeyRes = contact_it->second->eccKP().get_own_public_key_pem(peerPem1);
        auto loadKeyRes = _self.eccKP().load_peer_public_key_from_pem(peerPem1);

        if(_self.eccKP().encrypt(input, ciphertext_finalized, iv, tag_unencoded))       // inner encryption layer: ECC
        {
            if( //_self.des3Key().encrypt(ciphertext_unencoded, ciphertext_finalized) &&   // outer encryption layer: DES3
                Base64::encode(ciphertext_finalized, ciphertext) &&
                Base64::encode(tag_unencoded, tag) &&
                Base64::encode(iv, iv_encoded))
            {
                Json::Value jsonOutput;
                std::string output_str;
                output_str.assign(ciphertext.begin(), ciphertext.end());
                jsonOutput["content"] = output_str;

                output_str.clear();
                output_str.assign(iv_encoded.begin(), iv_encoded.end());
                jsonOutput["iv"] = output_str;
                
                output_str.clear();
                output_str.assign(tag.begin(), tag.end());
                jsonOutput["tag"] = output_str;
                jsonOutput["timestamp"] = (uint64_t)time(nullptr);         // TODO: Improve

                if(_self.eccKP().sign_with_own_key(ciphertext, signature))
                {
                    HASH hash;

                    // Note: Need to do something like this to defend against replay attacks
                    std::string signature_str = Base64::encode(signature);
                    std::stringstream ss;
                    ss << signature_str << "_" << jsonOutput["timestamp"].asInt64();

                    std::string hashed_signature_str;
                    if(hash.digest(ss.str(), hashed_signature_str, _hash_algo))
                    {
                        Json::Value signaturePayload;
                        signaturePayload["algo"] = _hash_algo;
                        signaturePayload["value"] = signature_str;
                        signaturePayload["digest"] = hashed_signature_str;
                        jsonOutput["sig"] = signaturePayload;

                        Json::StreamWriterBuilder wbuilder;
                        if(_debug_pretty_print)
                            wbuilder["indentation"] = "  ";
                        else
                            wbuilder["indentation"] = "";
                        auto outputStr = Json::writeString(wbuilder, jsonOutput);

                        std::string outputStrEncoded;
                        if(Base64::encode(outputStr, outputStrEncoded))
                        {
                            output.clear();
                            output = std::vector<uint8_t>(outputStrEncoded.begin(), outputStrEncoded.end());
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool iar::utils::SCTransceiver::DecryptDecodeContent(const std::string& contact, const std::vector<uint8_t>& input, std::vector<uint8_t>& output)
{
    auto contact_it = _contacts.find(contact);
    if(contact_it != _contacts.end())
    {
        // Base64 decode
        std::vector<uint8_t> decodedInput;
        if(Base64::decode(input, decodedInput))
        {
            std::string decodedInputStr(decodedInput.begin(), decodedInput.end());
            std::ifstream ifs;
            if (!ifs) return false;

            Json::Value jsonPayload;
            Json::CharReaderBuilder builder;
            std::string errs;
            //printf("decodedInputStr: %s\n", decodedInputStr.data());

            if (!builder.newCharReader()->parse(decodedInputStr.data(),
                decodedInputStr.data() + decodedInputStr.size() * sizeof(uint8_t), &jsonPayload, &errs) )
            {
                return false;
            }

            // Extract content, tag & timestamp
            std::string content = jsonPayload["content"].asString();
            std::string iv = jsonPayload["iv"].asString();
            std::string tag = jsonPayload["tag"].asString();
            int64_t timestamp = jsonPayload["timestamp"].asInt64();

            std::string iv_decoded, content_decoded, tag_decoded;
            if( Base64::decode(iv, iv_decoded) &&
                Base64::decode(content, content_decoded) &&
                Base64::decode(tag, tag_decoded))
            {
                std::vector<uint8_t> iv_decoded_vect(iv_decoded.begin(), iv_decoded.end());
                std::vector<uint8_t> content_decoded_vect(content_decoded.begin(), content_decoded.end());
                std::vector<uint8_t> tag_decoded_vect(tag_decoded.begin(), tag_decoded.end());
                std::vector<uint8_t> content_finalized;

                if(_self.eccKP().decrypt(content_decoded_vect, output, iv_decoded_vect, tag_decoded_vect)
                    //  && _self.des3Key().decrypt(content_finalized, output)
                    )
                {
                    // Calculate content signature & verify against signature object
                    // Extract signature object
                    auto signatureJsonObj = jsonPayload["sig"];
                    std::string sigAlgo = signatureJsonObj["algo"].asString();
                    std::string sigValue = signatureJsonObj["value"].asString();
                    std::string sigDigest = signatureJsonObj["digest"].asString();

                    std::vector<uint8_t> signatureVect(sigValue.begin(), sigValue.end()), signatureDecoded;
                    Base64::decode(signatureVect, signatureDecoded);
                    //std::cout << "signature: " << sigValue << "\n";

                    std::string peerPem1;
                    auto getKeyRes = contact_it->second->eccKP().get_own_public_key_pem(peerPem1);
                    auto loadKeyRes = _self.eccKP().load_peer_public_key_from_pem(peerPem1);

                    if(_self.eccKP().verify_with_peer_key(content, sigValue))
                    {
                        std::stringstream ss;
                        ss << sigValue << "_" << timestamp;

                        std::string hashed_signature_str; HASH hash;
                        if(hash.digest(ss.str(), hashed_signature_str, sigAlgo))
                        {
                            if(hashed_signature_str == sigDigest) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}


bool iar::utils::SCTransceiver::EncryptEncodeContent(const std::string& contact, const std::string& input, std::string& output)
{
    std::vector<uint8_t> input_vect(input.begin(), input.end());
    std::vector<uint8_t> output_vect;
    auto result = EncryptEncodeContent(contact, input_vect, output_vect);

    output.clear();
    output = std::string(output_vect.begin(), output_vect.end());
    return result;
}

bool iar::utils::SCTransceiver::DecryptDecodeContent(const std::string& contact, const std::string& input, std::string& output)
{
    std::vector<uint8_t> input_vect(input.begin(), input.end());
    std::vector<uint8_t> output_vect;
    auto result = DecryptDecodeContent(contact, input_vect, output_vect);

    output.clear();
    output = std::string(output_vect.begin(), output_vect.end());
    return result;

}