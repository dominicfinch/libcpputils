#include "server.h"

#include "database.h"
#include "base64.h"
#include "hash.h"
#include <iostream>
#include <functional>


iar::app::SecChatServer::SecChatServer(jsonrpc::AbstractServerConnector &connector): AbstractServer<SecChatServer>(connector)
{
    // Register JSON-RPC method: registerDevice
    this->bindAndAddMethod(
        jsonrpc::Procedure(
            "registerDevice",
            jsonrpc::PARAMS_BY_NAME,
            jsonrpc::JSON_OBJECT,          // return type
            "user_id",     jsonrpc::JSON_STRING,
            "device_id",   jsonrpc::JSON_STRING,
            "public_key",  jsonrpc::JSON_STRING,
            nullptr),
        &SecChatServer::registerDevice
    );



}

bool iar::app::SecChatServer::Initialise(const Json::Value& config)
{
    auto logConfig = config["logging"];
    auto dbConfig = config["database"];
    auto success = initialize_logging(logConfig, logInfo) &&
        initialize_database(dbConfig, dbInfo);

    return success;
}


bool iar::app::SecChatServer::initialize_logging(const Json::Value& config, iar::app::LogInfo& lInfo)
{

    lInfo.level = config["level"].asString();
    lInfo.pattern = config["pattern"].asString();
    lInfo.output = config["output"].asString();
    lInfo.output_path = config["output-path"].asString();
    lInfo.max_size = config["max-size"].asInt();
    lInfo.max_files = config["max-files"].asInt();

    //logPtr = std::make_shared<spdlog::logger>(spdlog::logger());
    if(lInfo.output.compare("console") == 0 )
    {
        logPtr = spdlog::stdout_color_mt("console-log");
    } else if(lInfo.output.compare("file") == 0)
    {
        logPtr = spdlog::basic_logger_mt("file-log", lInfo.output_path);
    } else if(lInfo.output.compare("rotating-file") == 0) {
        logPtr = spdlog::rotating_logger_mt("rot-file-log", lInfo.output_path, lInfo.max_size, lInfo.max_files);
    }

    if(logPtr.use_count() > 0) {
        logPtr->set_pattern(lInfo.pattern);
        spdlog::level::level_enum lvl;
        if(lInfo.level == "trace") {
            lvl = spdlog::level::trace;
        } else if(lInfo.level == "debug") {
            lvl = spdlog::level::debug;
        } else if(lInfo.level == "info") {
            lvl = spdlog::level::info;
        } else if(lInfo.level == "warn") {
            lvl = spdlog::level::warn;
        } else if(lInfo.level == "error") {
            lvl = spdlog::level::err;
        } else if(lInfo.level == "critical") {
            lvl = spdlog::level::critical;
        }
        logPtr->set_level(lvl);
        logPtr->info("Created new logger instance '{}'", logPtr->name());
    }

    return true;
}

bool iar::app::SecChatServer::initialize_database(const Json::Value& config, iar::app::DatabaseInfo& dInfo)
{
    dInfo.host = config["host"].asString();
    dInfo.user = config["user"].asString();
    dInfo.pass = config["pass"].asString();
    dInfo.port = config["port"].asInt();
    dInfo.db_name = config["db"].asString();
    dInfo.ssl_mode = config["ssl.mode"].asString();
    dInfo.ssl_rootcert = config["ssl.rootcert"].asString();
    dInfo.ssl_cert = config["ssl.cert"].asString();
    dInfo.ssl_key = config["ssl.key"].asString();

    std::stringstream ss;
    ss << "host=" << dInfo.host << " ";
    ss << "port=" << dInfo.port << " ";
    ss << "user=" << dInfo.user << " ";
    ss << "password=" << dInfo.pass << " ";
    ss << "dbname=" << dInfo.db_name << " ";
    ss << "sslmode=" << dInfo.ssl_mode << " ";

    if( dInfo.ssl_mode.compare("verify-ca") == 0 ) {
        ss << "sslrootcert=" << dInfo.ssl_rootcert << " ";
    } else if( dInfo.ssl_mode.compare("verify-full") == 0 ) {
        ss << "sslrootcert=" << dInfo.ssl_rootcert << " ";
        ss << "sslcert=" << dInfo.ssl_cert << " ";
        ss << "sslkey=" << dInfo.ssl_key << " ";
    }
    DatabaseManager::instance().initialize(ss.str());
    return true;
}


void iar::app::SecChatServer::registerDevice(const Json::Value& request, Json::Value& response)
{
    try {
        // Extract parameters
        std::string user_id   = request["user_id"].asString();
        std::string device_id = request["device_id"].asString();
        std::string pubkey    = request["public_key"].asString();

        if (user_id.empty() || device_id.empty() || pubkey.empty()) {
            throw std::runtime_error("Missing required parameter");
        }

        // Store in DB
        DatabaseManager::instance().addDevice(user_id, device_id, pubkey);

        // Build response
        response["status"]  = "success";
        response["message"] = "Device registered successfully";
    }
    catch (const std::exception &e) {
        response["status"]  = "error";
        response["message"] = e.what();
    }
}