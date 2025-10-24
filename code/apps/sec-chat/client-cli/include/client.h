#pragma once

#include <string>
#include <sstream>
#include <memory>
#include <iostream>

#include "ecc.h"
#include "rsa.h"
#include "sc/contact.h"
#include "constants.h"

#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/client.h>

namespace iar { namespace app {

    class SecChatClient
    {
        public:


            bool Initialize(const Json::Value& config) {
                // Open port
                auto port_number = config["port"].asInt();
                port_number = port_number == 0 ? DEFAULT_SERVER_PORT : port_number;

                auto host = config["host"].asString();
                host = host.empty() ? "0.0.0.0" : host;
                
                std::stringstream ss;
                ss << "http://" << host << ":" << port_number;
                //std::cout << " - Connecting to: " << ss.str() << "\n";    // TODO: Integrate logging

                jsonrpc::HttpClient httpClient(ss.str());
                //_rpcClient = std::make_unique<jsonrpc::Client>(jsonrpc::Client(httpClient));
                return true;
            }

            // Thin wrapper around jsonrpc call
            Json::Value CallMethod(const std::string& method, const Json::Value& content)
            {
                std::cout << "CALLING RPC METHOD!\n";
                return _rpcClient->CallMethod(method, content);
            }

            utils::SCContact& Self() { return _ownContact; }

        private:
            utils::SCContact _ownContact;
            jsonrpc::HttpClient * _httpClient = nullptr;
            jsonrpc::Client * _rpcClient = nullptr;
    };

}}