
#include <iostream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <pqxx/pqxx>

#include "constants.h"
#include "server_cmd_args.h"

#include "file.h"
#include "string_helpers.h"
#include "certificate.h"
#include "server.h"

std::unique_ptr<jsonrpc::HttpServer> httpServerPtr;
std::unique_ptr<iar::app::SecurityService> secServerPtr;

bool initalize_channel(const Json::Value& config, iar::app::ServerInfo& sInfo) {
    auto success = false;

    sInfo.port_number = config["port"].asInt() > 0 ? config["port"].asInt() : DEFAULT_SERVER_PORT;
    sInfo.ssl_enabled = config["ssl.enabled"].asBool();
    sInfo.ssl_cert = config["ssl.cert"].asString();
    sInfo.ssl_key = config["ssl.key"].asString();
    sInfo.threads = config["threads"].asInt() > 0 ? config["threads"].asInt() : DEFAULT_SERVER_THREAD_NUM;

    if(sInfo.ssl_enabled) {
        if(!sInfo.ssl_cert.empty() && !sInfo.ssl_key.empty())
        {
            if(iar::utils::file_exists(sInfo.ssl_cert) && iar::utils::file_exists(sInfo.ssl_key))
            {
                httpServerPtr = std::make_unique<jsonrpc::HttpServer>(sInfo.port_number, sInfo.ssl_cert, sInfo.ssl_key, sInfo.threads);
                secServerPtr = std::make_unique<iar::app::SecurityService>(*httpServerPtr.get());
                success = true;
            } else
            {
                std::cout << " - Error: Unable to resolve file paths for:\n\tssl.cert: " << sInfo.ssl_cert << "\n\tssl.key: " << sInfo.ssl_key << "\n";
            }
        } else {
            // If ssl enabled then cert and key must be set
            std::cout << " - Error: If ssl enabled then cert and key must be set\n";
        }
    } else {
        httpServerPtr = std::make_unique<jsonrpc::HttpServer>(sInfo.port_number, "", "", sInfo.threads);
        secServerPtr = std::make_unique<iar::app::SecurityService>(*httpServerPtr.get());
        success = true;
    }
    return success;
}


int main(int argc, char * argv[])
{
    iar::app::SecurityServiceCmdArgParser cmdArgParser;

    if(cmdArgParser.parse(argc, argv) == 0)
    {
        iar::app::ServerInfo serverInfo;
        auto config = cmdArgParser.config();
        if(initalize_channel(config, serverInfo))
        {
            if ( secServerPtr->Initialise(config) && httpServerPtr->StartListening() )
            {
                secServerPtr->LogMessage(iar::utils::stringFormat("JSON-RPC server listening on port ", serverInfo.port_number));
                std::cin.get(); // wait for user input
                secServerPtr->StopListening();
            } else {
                std::cerr << "Error starting server" << std::endl;
            }
        } else {
            std::cerr << "Failed to initialize channel" << std::endl;
        }
    }
    return 0;
}