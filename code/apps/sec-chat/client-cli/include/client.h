#pragma once

#include <string>
#include <sstream>
#include <memory>
#include <iostream>

#include "sc/contact.h"
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/client.h>

namespace iar { namespace app {

    struct ClientInfo {
        std::string host;
        std::string ssl_cert;
        std::string ssl_key;
        int threads;
        int port_number;
        bool ssl_enabled = false;
    };

    class SecChatClient
    {
        public:
            bool Initialize(const Json::Value& config);

            // Thin wrapper around jsonrpc call
            Json::Value CallMethod(const std::string& method, const Json::Value& content) {
                std::cout << "CALLING METHOD!\n";
                return rpcClientPtr->CallMethod(method, content);
            }

            utils::SCContact& Self() { return ownContact; }

        private:

            ClientInfo  cInfo;
            utils::SCContact ownContact;

            std::unique_ptr<jsonrpc::HttpClient> httpClientPtr;
            std::unique_ptr<jsonrpc::Client> rpcClientPtr;
    };

}}