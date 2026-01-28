/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <grpc++/security/server_credentials.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <json/json.h>

#include "ecc.h"
#include "db/database.h"
#include "av/stream_manager.h"
//#include "av/stream_broadcaster.h"
#include "interfaces/node.h"

#include "rpc/server/camera.h"
#include "rpc/server/event_dispatch.h"
#include "rpc/server/streaming_service.h"

namespace iar { namespace app {

    template <typename T>
    struct ServiceInfoObject        // Doing it this way makes it easier to change underlying struct T without breaking compatibility
    {
        T * p = nullptr;
        ServiceInfoObject(): p(new T) {}
        ~ServiceInfoObject() { delete p; }

        T* operator->()
        {
            return p;
        }

        const T* operator->() const
        {
            return p;
        }
    };

    struct ServerInfo {
        int port_number;
        bool ssl_enabled = false;
        std::string ssl_cert;
        std::string ssl_key;
        int threads;
    };

    struct DatabaseInfo {
        std::string provider;
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
    
    struct StorageInfo {
        std::string provider;
        std::string bucket;
        std::string credentials;
    };


    class SecurityService: public security_service<Json::Value>
    {
    public:
        SecurityService();
        ~SecurityService();

        bool Initialize(Json::Value& configuration) override;
        bool Run() override;
        void Shutdown() override;

        Json::Value& Configuration() override { return _configuration; }
        std::unique_ptr<grpc::Server>& Server() { return _serverInstance; }
        std::vector<std::shared_ptr<spdlog::logger>>& Loggers() { return loggers; }

        void LogMessage(const Json::Value& obj, spdlog::level::level_enum lvl = spdlog::level::level_enum::info);
        void LogMessage(const std::string& msg, spdlog::level::level_enum lvl = spdlog::level::level_enum::info);
        void LogMessage(const char * msg, spdlog::level::level_enum lvl = spdlog::level::level_enum::info);

        template <class ... Args>
        void LogMessage(const std::string& format, Args ... args, int level=spdlog::level::info) {
            LogMessage(format.c_str(), args ... , level);
        }

        template <class ... Args>
        void LogMessage(const char * format, Args ... args, int level=spdlog::level::info) {
            for(auto& logPtr : Loggers()) {
                if(level == spdlog::level::trace) {
                    logPtr->trace(format, args ...);
                } else if(level == spdlog::level::debug) {
                    logPtr->debug(format, args ...);
                } else if(level == spdlog::level::info) {
                    logPtr->info(format, args ...);
                } else if(level == spdlog::level::warn) {
                    logPtr->warn(format, args ...);
                } else if(level == spdlog::level::err) {
                    logPtr->error(format, args ...);
                } else if(level == spdlog::level::critical) {
                    logPtr->critical(format, args ...);
                }
            }
        }

    protected:


    private:
        bool initialize_logging(const Json::Value& config);
        bool initialize_database(const Json::Value& config, ServiceInfoObject<DatabaseInfo>& dInfo);
        bool initialize_rpc(const Json::Value& config, ServiceInfoObject<ServerInfo>& serverInfo);
        bool initialize_tls(const Json::Value& config, ServiceInfoObject<ServerInfo>& serverInfo);

        // Configuration & setup vars //
        Json::Value _configuration;
        ServiceInfoObject<ServerInfo> serverInfo;
        ServiceInfoObject<DatabaseInfo> dbInfo;
        ServiceInfoObject<std::vector<StorageInfo>> storageInfo;
        bool _initialized = false;
        
        std::shared_ptr<av::StreamManager> _streamManager = nullptr;
        sql::DatabaseManager * dbManager = nullptr;
        std::vector<std::shared_ptr<spdlog::logger>> loggers;
        //iar::utils::ECC eccKey;

        // gRPC server stuff //
        std::thread * _grpcMasterThread = nullptr;
        std::unique_ptr<grpc::Server> _serverInstance = nullptr;
        std::shared_ptr<grpc::ServerCredentials> _credentials;
        grpc::SslServerCredentialsOptions _credentials_options;

        std::shared_ptr<CameraService> _cameraService = nullptr;
        std::shared_ptr<StreamingService> _streamingService = nullptr;
        std::shared_ptr<EventDispatchService> _eventDispatchService = nullptr;


    };


}}