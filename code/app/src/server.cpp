/*
 © Copyright 2025 Dominic Finch
*/

#include "server.h"

#include "database.h"
#include "base64.h"
#include "hash.h"
#include "string_helpers.h"

#include <limits>
#include <iostream>
#include <sstream>
//#include <functional>


iar::app::SecurityService::SecurityService(jsonrpc::AbstractServerConnector &connector): AbstractServer<SecurityService>(connector)
{
    // Register JSON-RPC method: registerClient
    this->bindAndAddMethod(
        jsonrpc::Procedure(
            "registerClient",
            jsonrpc::PARAMS_BY_NAME,
            jsonrpc::JSON_OBJECT,          // return type
            "client_id",     jsonrpc::JSON_STRING,
            "key_type", jsonrpc::JSON_STRING,
            "public_key",  jsonrpc::JSON_STRING,
            "nonce", jsonrpc::JSON_INTEGER,
            "dt", jsonrpc::JSON_STRING,             // ISO 8601 format for UTC is represented as "YYYY-MM-DDTHH:MM:SSZ" or "YYYY-MM-DDTHH:MM:SS+[INT]:[INT]"
            "sign_hash", jsonrpc::JSON_STRING,
            nullptr),
        &SecurityService::registerClient
    );

    // Register JSON-RPC method: registerDevice
    /*
    this->bindAndAddMethod(
        jsonrpc::Procedure(
            "registerDevice",
            jsonrpc::PARAMS_BY_NAME,
            jsonrpc::JSON_OBJECT,          // return type
            "user_id",     jsonrpc::JSON_STRING,
            "device_id",   jsonrpc::JSON_STRING,
            "public_key",  jsonrpc::JSON_STRING,
            nullptr),
        &SecurityService::registerDevice
    );
    */

}

iar::app::SecurityService::~SecurityService()
{
    loggersInfo.clear();
}

void iar::app::SecurityService::LogMessage(const Json::Value& obj, spdlog::level::level_enum lvl)
{
    std::stringstream ss;
    Json::StreamWriterBuilder writerBuilder;
    writerBuilder["indentation"] = "  "; // 2 spaces for readability
    std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());
    writer->write(obj, &ss);
    LogMessage(ss.str());
}

void iar::app::SecurityService::LogMessage(const std::string& msg, spdlog::level::level_enum lvl)
{
    for(auto logger : loggers)
    {
        switch (lvl)
        {
            case spdlog::level::level_enum::critical:
                logger->critical(msg);
                logger->enable_backtrace(10);
                logger->dump_backtrace();
                break;
            
            case spdlog::level::level_enum::err:
                logger->error(msg);
                logger->enable_backtrace(10);
                logger->dump_backtrace();
                break;
            
            case spdlog::level::level_enum::warn:
                logger->warn(msg);
                break;
            
            case spdlog::level::level_enum::info:
                logger->info(msg);
                break;
            
            case spdlog::level::level_enum::debug:
                logger->debug(msg);
                break;
            
            case spdlog::level::level_enum::trace:
                logger->trace(msg);
                break;
            
            default:
                break;
        }
    }
}

bool iar::app::SecurityService::Initialise(const Json::Value& config)
{
    auto dbConfig = config["database"];

    auto success = initialize_logging(config, loggersInfo) &&
        initialize_database(dbConfig, dbInfo);
    return success;
}


bool iar::app::SecurityService::initialize_logging(const Json::Value& config, std::vector<iar::app::LogInfo>& loggersInfo)
{
    loggersInfo.clear();
    for(auto lc : config["logging"])
    {
        LogInfo lInfo;

        lInfo.level = lc["level"].asString();
        lInfo.pattern = lc["pattern"].asString();
        lInfo.output = lc["output"].asString();
        lInfo.output_path = lc["output-path"].asString();
        lInfo.max_size = lc["max-size"].asInt();
        lInfo.max_files = lc["max-files"].asInt();

        //logPtr = std::make_shared<spdlog::logger>(spdlog::logger());
        std::shared_ptr<spdlog::logger> logPtr;
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

            loggersInfo.push_back(lInfo);
            loggers.push_back(logPtr);
            logPtr->info("Created new logger instance '{}'", logPtr->name());
        } else {
            std::cout << " - Error: Unrecognized output specified: '" << lInfo.output << "'\n";
        }
    }
    return true;
}

bool iar::app::SecurityService::initialize_database(const Json::Value& config, iar::app::DatabaseInfo& dInfo)
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


void iar::app::SecurityService::registerClient(const Json::Value& request, Json::Value& response)
{
    try
    {
        // 0. Log client request
        LogMessage(utils::stringFormat("Requested endpoint: %s", __METHOD_NAME_CSTR__));
        LogMessage(request, spdlog::level::level_enum::debug);

        // 1. Extract various request details
        auto client_id = request["client_id"].asString();
        auto key_type = request["key_type"].asString();
        auto public_key = request["public_key"].asString();
        auto nonce = request["nonce"].asUInt();
        auto dt = request["dt"].asString();
        auto sign_hash = request["sign_hash"].asString();

        // 2. Validate request details
        auto isRequestValid = false;
        if(iar::utils::is_uuid(client_id))
        {
            int nonceMin = 0, nonceMax = std::numeric_limits<uint32_t>::max();
            if((nonce >= nonceMin) && (nonce <= nonceMax))
            {

                // Validate key_type

                // Validate dt

                // Validate sign_hash




                auto decodedPubKey = utils::Base64::decode(public_key);



                // valid


                isRequestValid = true;

            } else {
                // invalid
                std::string errMsg = utils::stringFormat("Invalid request nonce detected: %d", nonce);
                LogMessage(errMsg, spdlog::level::err);
            }
        }

        // 3. Update database
        if(isRequestValid)
        {
            //DatabaseManager()
        } else {
            std::runtime_error ex("Request failed validation. Please try again");
            throw ex;
        }
    } catch (const std::exception &e) {
        response["status"]  = "error";
        response["message"] = e.what();
    }
}




void iar::app::SecurityService::registerDevice(const Json::Value& request, Json::Value& response)
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