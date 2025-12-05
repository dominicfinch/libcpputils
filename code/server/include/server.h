/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <jsonrpccpp/server/connectors/httpserver.h>
#include <jsonrpccpp/server.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <pqxx/pqxx>


#include "ecc.h"

namespace iar { namespace app {

    struct ServerInfo {
        int port_number;
        bool ssl_enabled = false;
        std::string ssl_cert;
        std::string ssl_key;
        int threads;
    };

    struct DatabaseInfo {
        std::string host;
        std::string user;
        std::string pass;
        int port;
        std::string db_name;
        std::string ssl_mode;
        std::string ssl_rootcert;
        std::string ssl_cert;
        std::string ssl_key;
    };

    struct LogInfo {
        std::string level;
        std::string pattern;
        std::string output;
        std::string output_path;
        int max_size;
        int max_files;
    };
    


    class SecurityService : public jsonrpc::AbstractServer<SecurityService> {
    public:
        SecurityService(jsonrpc::AbstractServerConnector &connector);
        ~SecurityService();

        bool Initialise(const Json::Value& config);

        void LogMessage(const Json::Value& obj, spdlog::level::level_enum lvl = spdlog::level::level_enum::info);
        void LogMessage(const std::string& msg, spdlog::level::level_enum lvl = spdlog::level::level_enum::info);

    protected:
        
        void registerClient(const Json::Value& request, Json::Value& response);
        void registerDevice(const Json::Value& request, Json::Value& response);


    private:
        bool initialize_logging(const Json::Value& config, std::vector<LogInfo>& lInfo);
        bool initialize_database(const Json::Value& config, DatabaseInfo& dInfo);

        std::vector<LogInfo> loggersInfo;
        DatabaseInfo dbInfo;
        
        std::vector<std::shared_ptr<spdlog::logger>> loggers;
        //iar::utils::ECC eccKey;
        
    };


}}