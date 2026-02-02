/*
 © Copyright 2025 Dominic Finch
*/
#include <grpc++/server_builder.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include "server.h"
#include "file.h"
#include "string_helpers.h"

#include <limits>
#include <iostream>
#include <sstream>
#include <regex>


iar::app::SecurityService::SecurityService()
{
    
}

iar::app::SecurityService::~SecurityService()
{
    Shutdown();
}

bool iar::app::SecurityService::Initialize(Json::Value& configuration)
{
    auto dbConfig = configuration["database"];
    _initialized = initialize_logging(configuration)            &&
                    initialize_database(dbConfig, database_info())       &&
                    initialize_tls(configuration, server_info())   &&
                    initialize_rpc(configuration, server_info());
    return _initialized;
}

bool iar::app::SecurityService::initialize_logging(const Json::Value& config)
{
    for(auto lc : config["logging"])
    {
        ServiceInfoObject<LogInfo> lInfo;

        lInfo->level = lc["level"].asString();
        lInfo->pattern = lc["pattern"].asString();
        lInfo->output = lc["output"].asString();
        lInfo->output_path = lc["output-path"].asString();
        lInfo->max_size = lc["max-size"].asInt();
        lInfo->max_files = lc["max-files"].asInt();

        // Get datetime and replace placeholders
        auto now = std::chrono::system_clock::now();
        time_t tt = std::chrono::system_clock::to_time_t(now);
        tm utc_tm = *gmtime(&tt);

        lInfo->output_path = std::regex_replace(lInfo->output_path, std::regex("%Y"), std::to_string(utc_tm.tm_year + 1900));

        std::stringstream ss;
        ss << std::setfill('0') << std::setw(2) << std::to_string(utc_tm.tm_mon + 1);
        lInfo->output_path = std::regex_replace(lInfo->output_path, std::regex("%m"), ss.str());

        ss.str(""); ss.clear();
        ss << std::setfill('0') << std::setw(2) << utc_tm.tm_mday;
        lInfo->output_path = std::regex_replace(lInfo->output_path, std::regex("%d"), ss.str());

        //logPtr = std::make_shared<spdlog::logger>(spdlog::logger());
        std::shared_ptr<spdlog::logger> logPtr;
        if(lInfo->output.compare("console") == 0 )
        {
            logPtr = spdlog::stdout_color_mt("console-log");
        } else if(lInfo->output.compare("file") == 0)
        {
            logPtr = spdlog::basic_logger_mt("file-log", lInfo->output_path);
        } else if(lInfo->output.compare("rotating-file") == 0)
        {
            logPtr = spdlog::rotating_logger_mt("rot-file-log", lInfo->output_path, lInfo->max_size, lInfo->max_files);
        }

        if(logPtr.use_count() > 0) {
            logPtr->set_pattern(lInfo->pattern);
            spdlog::level::level_enum lvl;
            if(lInfo->level == "trace") {
                lvl = spdlog::level::trace;
            } else if(lInfo->level == "debug") {
                lvl = spdlog::level::debug;
            } else if(lInfo->level == "info") {
                lvl = spdlog::level::info;
            } else if(lInfo->level == "warn") {
                lvl = spdlog::level::warn;
            } else if(lInfo->level == "error") {
                lvl = spdlog::level::err;
            } else if(lInfo->level == "critical") {
                lvl = spdlog::level::critical;
            }
            logPtr->set_level(lvl);

            Loggers().push_back(logPtr);
            logPtr->info("Created new logger instance '{}'", logPtr->name());
        } else {
            std::cout << " - Error: Unrecognized output specified: '" << lInfo->output << "'\n";
        }
    }
    return true;
}

bool iar::app::SecurityService::initialize_database(const Json::Value& config, ServiceInfoObject<iar::app::DatabaseInfo>& dInfo)
{
    dInfo->provider = config["provider"].asString();
    dInfo->host = config["host"].asString();
    dInfo->user = config["user"].asString();
    dInfo->pass = config["pass"].asString();
    dInfo->port = config["port"].asInt();
    dInfo->db_name = config["db"].asString();
    dInfo->ssl_mode = config["tls.mode"].asString();
    dInfo->ssl_rootcert = config["tls.rootcert"].asString();
    dInfo->ssl_cert = config["tls.cert"].asString();
    dInfo->ssl_key = config["tls.key"].asString();

    std::stringstream ss;
    ss << "host=" << dInfo->host << " ";
    ss << "port=" << dInfo->port << " ";
    ss << "user=" << dInfo->user << " ";
    ss << "password=" << dInfo->pass << " ";
    ss << "dbname=" << dInfo->db_name << " ";
    ss << "sslmode=" << dInfo->ssl_mode << " ";

    if( dInfo->ssl_mode.compare("verify-ca") == 0 ) {
        ss << "sslrootcert=" << dInfo->ssl_rootcert << " ";
    } else if( dInfo->ssl_mode.compare("verify-full") == 0 ) {
        ss << "sslrootcert=" << dInfo->ssl_rootcert << " ";
        ss << "sslcert=" << dInfo->ssl_cert << " ";
        ss << "sslkey=" << dInfo->ssl_key << " ";
    }
    
    // TODO: Improve this. Use dInfo->provider instead.
    const sql::DatabaseManager::Config dbConf
    {
        sql::DatabaseManager::Backend::Postgres,
        ss.str()
    };

    _dbManager = std::shared_ptr<sql::DatabaseManager>(new sql::DatabaseManager);
    if(_dbManager->initialize_connection_pool(dbConf))
    {
        LogMessage("Successfully set up database connection pool");
        _dbManager->create_schema(false);
        return true;
    } else {
        LogMessage("Failed to set up database connection pool", spdlog::level::err);
    }
    return false;
}

bool iar::app::SecurityService::initialize_tls(const Json::Value& config, ServiceInfoObject<ServerInfo>& serverInfo)
{
    bool init_tls = false;

    serverInfo->ssl_enabled = config["tls.enabled"].asBool();
    serverInfo->ssl_cert = config["tls.cert"].asString();
    serverInfo->ssl_key = config["tls.key"].asString();
    serverInfo->port_number = config["port"].asInt();
    serverInfo->threads = config["threads"].asInt();

    if(serverInfo->ssl_enabled) {
        std::string publicKey, privateKey;
        bool readSSLCert = utils::read_file_contents(serverInfo->ssl_cert, publicKey);
        bool readSSLPKey = utils::read_file_contents(serverInfo->ssl_key, privateKey);

        if(readSSLCert && readSSLPKey) {
            // TODO: Generalize some of this logic
            _credentials_options = grpc::SslServerCredentialsOptions(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY);
            grpc::SslServerCredentialsOptions::PemKeyCertPair keyCertPair = { privateKey, publicKey };

            _credentials_options.force_client_auth = false;
            _credentials_options.pem_key_cert_pairs.push_back(keyCertPair);
            _credentials = grpc::SslServerCredentials(_credentials_options);

            LogMessage("Successfully loaded TLS certificate and key from file");
            init_tls = true;
        } else {
            LogMessage(utils::stringFormat("Error loading TLS certificate and private key from file.\n\tCertificate Path: %s\n\tPrivate Key Path:%s", serverInfo->ssl_cert, serverInfo->ssl_key));
        }
    } else {
        _credentials = grpc::InsecureServerCredentials();
        LogMessage("Beware, SSL is disabled. Will be running on insecure channel");
        init_tls = true;
    }
    return init_tls;
}

bool iar::app::SecurityService::initialize_rpc(const Json::Value& config, ServiceInfoObject<ServerInfo>& serverInfo)
{
    _grpcMasterThread = new std::thread([&]() -> bool {
        if(_initialized)
        {
            if(_streamManager == nullptr)
            {
                _streamManager = std::shared_ptr<iar::av::StreamManager>(new iar::av::StreamManager);
            } else {
                LogMessage("Stream manager already initialized", spdlog::level::warn);
            }

            /// GRPC services ///
            if(_cameraService == nullptr)
                _cameraService = std::shared_ptr<CameraService>(new CameraService(this));
            else
                LogMessage("Camera service already initialized", spdlog::level::warn);
            
            if(_streamingService == nullptr)
            {
                _streamingService = std::shared_ptr<StreamingService>(new StreamingService(this));

            } else
                LogMessage("Streaming service already initialized", spdlog::level::warn);
            
            if(_eventDispatchService == nullptr)
                _eventDispatchService = std::shared_ptr<EventDispatchService>(new EventDispatchService(this));
            else
                LogMessage("Event dispatch service already initialized", spdlog::level::warn);

            if(_serverInstance == nullptr)
            {
                std::stringstream ss;
                ss << "0.0.0.0" << ":" << serverInfo->port_number;

                grpc::ServerBuilder builder;
                if(_initialized)
                {
                    auto serverAddress = ss.str();
                    LogMessage(utils::stringFormat("GRPC Server listening at: %s", serverAddress));
                    builder.AddListeningPort(serverAddress, _credentials);

                    builder.RegisterService(_cameraService.get());
                    builder.RegisterService(_streamingService.get());
                    builder.RegisterService(_eventDispatchService.get());

                    grpc::ResourceQuota rq;
                    rq.SetMaxThreads(serverInfo->threads);
                    builder.SetResourceQuota(rq);

                    _serverInstance = builder.BuildAndStart();
                    _serverInstance->Wait();
                    return true;
                }
            }
        };
        return false;
    });
    return true;
}

bool iar::app::SecurityService::Run()
{
    if(_initialized) {
        if(_grpcMasterThread != nullptr)
        {
            //_grpcMasterThread->detach();      // Non-Blocking (use this if we want multiple services running alongside grpc server)
            _grpcMasterThread->join();          // Blocking. This will halt execution until _serverInstance->Shutdown() is called (and that happens when the signalHandler is called)
            return true;
        } else {
            LogMessage("No master thread found. Unable to continue", spdlog::level::err);
        }
    } else {
        LogMessage("Attempting to run the node before it has properly initialized", spdlog::level::err);
    }
    return false;
}

void iar::app::SecurityService::Shutdown()
{
    LogMessage("Shutting down GRPC Server");
    if(_serverInstance != nullptr) {
        _serverInstance->Shutdown();
        _serverInstance = nullptr;
    }

    if(_grpcMasterThread != nullptr) {
        delete _grpcMasterThread;
        _grpcMasterThread = nullptr;
    }

    LogMessage("Deleting RPC Services");
    if(_cameraService != nullptr) {
        _cameraService.reset();
    }

    if(_streamingService != nullptr) {
        _streamingService.reset();
    }

    if(_eventDispatchService != nullptr) {
        _eventDispatchService.reset();
    }

    LogMessage("Shutting down stream manager");
    if(_streamManager != nullptr) {
        _streamManager.reset();
    }
    
    LogMessage("Closing database connection");
    if(_dbManager != nullptr) {
        _dbManager.reset();
    }
}