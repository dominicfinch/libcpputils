
#include "client.h"
#include "constants.h"


bool iar::app::SecChatClient::Initialize(const Json::Value& config)
{
    cInfo.port_number = config["port"].asInt() > 0 ? config["port"].asInt() : DEFAULT_SERVER_PORT;
    cInfo.host = !config["host"].asString().empty() ? config["host"].asString() : "127.0.0.1";

    cInfo.ssl_enabled = config["ssl.enabled"].asBool();
    cInfo.ssl_cert = config["ssl.cert"].asString();
    cInfo.ssl_key = config["ssl.key"].asString();
    cInfo.threads = config["threads"].asInt();
    
    std::stringstream ss;
    if(cInfo.ssl_enabled) {
        ss << "https://";
    } else {
        ss << "http://";
    }

    //std::cout << "sInfo.ssl_cert: " << cInfo.ssl_cert << "\n";
    //std::cout << "sInfo.ssl_key: " << cInfo.ssl_key << "\n";

    ss << cInfo.host << ":" << cInfo.port_number;
    std::cout << "Connecting to: " << ss.str() << "\n";
    httpClientPtr = std::make_unique<jsonrpc::HttpClient>(ss.str());

    /*
    httpClientPtr = std::make_unique<jsonrpc::HttpClient>(
        cInfo.port_number,
        cInfo.ssl_cert,   // client cert (optional)
        cInfo.ssl_key,    // client key (optional)
        cInfo.threads
    );
    */
    //httpClientPtr->SetCAFile("path/to/ca_cert.pem");

    rpcClientPtr = std::unique_ptr<jsonrpc::Client>(new jsonrpc::Client(*httpClientPtr));

    //httpClientPtr->SetVerifyPeer(false);
    //httpClientPtr->SetVerifyHost(false);
    return true;
}
