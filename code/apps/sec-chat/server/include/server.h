#pragma once

#include <jsonrpccpp/server/connectors/httpserver.h>
#include <jsonrpccpp/server.h>

#include "sc/address_book.h"

namespace iar { namespace app { 
    
    class SecChatServer : public jsonrpc::AbstractServer<SecChatServer> {
    public:
        SecChatServer(jsonrpc::AbstractServerConnector &connector): AbstractServer<SecChatServer>(connector)
        {
            this->bindAndAddMethod(
                jsonrpc::Procedure("open_channel", jsonrpc::PARAMS_BY_NAME,
                    jsonrpc::JSON_OBJECT, "rsa.pubkey",
                    jsonrpc::JSON_OBJECT, "ecc.pubkey",
                    jsonrpc::JSON_OBJECT, NULL),
                &SecChatServer::open_channel);
        }

        // Methods to open a channel
        void open_channel(const Json::Value& request, Json::Value& response);
        void close_channel(const Json::Value& request, Json::Value& response);
        void view_contacts(const Json::Value& request, Json::Value& response);

    private:
        utils::SCAddressBook _addressBook;
    };


}}