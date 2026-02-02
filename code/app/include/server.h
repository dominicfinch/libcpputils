/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <grpc++/security/server_credentials.h>

#include "interfaces/node.h"
#include "db/database.h"
#include "av/stream_manager.h"
#include "av/stream_broadcaster.h"

#include "rpc/server/camera.h"
#include "rpc/server/event_dispatch.h"
#include "rpc/server/streaming_service.h"

namespace iar { namespace app {

    class SecurityService:
        public security_service<Json::Value>,
        public security_service_context
    {
    public:
        SecurityService();
        ~SecurityService();

        bool Initialize(Json::Value& configuration) override;
        bool Run() override;
        void Shutdown() override;

        Json::Value& Configuration() override { return _configuration; }
        std::unique_ptr<grpc::Server>& Server() { return _serverInstance; }

        std::shared_ptr<sql::idatabase_manager> DatabaseManager() override { return _dbManager; }
        std::shared_ptr<av::istream_manager> StreamManager() override { return _streamManager; }

    private:
        bool initialize_logging(const Json::Value& config);
        bool initialize_database(const Json::Value& config, ServiceInfoObject<DatabaseInfo>& dInfo);
        bool initialize_rpc(const Json::Value& config, ServiceInfoObject<ServerInfo>& serverInfo);
        bool initialize_tls(const Json::Value& config, ServiceInfoObject<ServerInfo>& serverInfo);

        // Configuration & setup vars //
        Json::Value _configuration;
        bool _initialized = false;
        
        std::shared_ptr<av::StreamManager> _streamManager = nullptr;
        std::shared_ptr<sql::DatabaseManager> _dbManager = nullptr;

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