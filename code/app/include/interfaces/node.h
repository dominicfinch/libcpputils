
#pragma once

#include "av.h"
#include "db.h"

#include <json/json.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <memory>
#include <vector>
#include <grpc++/server.h>

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

    /*
        Dear maintainer,
            I thought it would be helpful to drop a quick comment to eplain what is the
            difference between the security_service and security_service_context. In a
            nutshell, the main SecurityService implements security_service and manages
            all the individual GRPC IO services (i.e. implemented proto files).
            Something like this:

            security_service
                -> camera_service
                -> event_service
                -> streaming_service
            
            The problem is that often the individual services often need to know about
            the security_service interface so we have a circular dependency A -> B -> A -> ...
            To solve this problem (and to ensure some sensible safeguards are in place)
            it is necessary for the individual services to have a definition for a
            security_service_context. This allows the individual services to call back to
            methods within their parent class.
        
        BEWARE: Extreme care should be taken in the context of multi-threading and dynamically
            allocated heap variables since there is self-reference in this structure. When
            a client makes a request to the grpc server instance the given service will request
            a thread from the allocated thread pool and use that to complete the request.. the
            issue comes from the fact multiple requests to a given service could interfere with
            each other since they will both have the same security_service_context reference (i.e.
            all grpc services will point back to the same parent instance, so theoretically if
            multiple requests, via multiple threads were to interact with the same underling
            variables in security_service_context it could cause race-conditions, data-corruption,
            segfaults and all sorts of other things.
    
    */
    
    /*
        This is the full interface which defines the security_service
    */
    template <class service_settings>
    class security_service {
        public:
            virtual bool Initialize(service_settings& configuration) = 0;
            virtual bool Run() = 0;
            virtual void Shutdown() = 0;
            virtual std::unique_ptr<grpc::Server>& Server() = 0;
            virtual service_settings& Configuration() = 0;
    };


    /*
        This is the slim interface which defines the security_service_context
    */
    class security_service_context {
        public:
            security_service_context() = default;
            ~security_service_context()
            {
                loggers.clear();
            }


            virtual void LogMessage(const Json::Value& obj, spdlog::level::level_enum lvl = spdlog::level::level_enum::info)
            {
                std::stringstream ss;
                Json::StreamWriterBuilder writerBuilder;
                writerBuilder["indentation"] = "  "; // 2 spaces for readability
                std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());
                writer->write(obj, &ss);
                LogMessage(ss.str(), lvl);
            }

            void LogMessage(const std::string& msg, spdlog::level::level_enum lvl)
            {
                for(auto logger : Loggers())
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

            virtual void LogMessage(const char * msg, spdlog::level::level_enum lvl = spdlog::level::level_enum::info)
            {
                LogMessage(std::string(msg), lvl);
            }

            template <class ... Args>
            void LogMessage(const std::string& format, Args ... args, int level=spdlog::level::info)
            {
                LogMessage(format.c_str(), args ... , level);
            }

            template <class ... Args>
            void LogMessage(const char * format, Args ... args, int level=spdlog::level::info)
            {
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
                        logPtr->enable_backtrace(10);
                        logPtr->dump_backtrace();
                    } else if(level == spdlog::level::critical) {
                        logPtr->critical(format, args ...);
                        logPtr->enable_backtrace(10);
                        logPtr->dump_backtrace();
                    }
                }
            }

            std::vector<std::shared_ptr<spdlog::logger>>& Loggers() { return loggers; }

            ServiceInfoObject<ServerInfo>& server_info() { return serverInfo; }
            ServiceInfoObject<DatabaseInfo>& database_info() { return dbInfo; }
            ServiceInfoObject<std::vector<StorageInfo>>& storage_info() { return storageInfo; }

            virtual std::shared_ptr<sql::idatabase_manager> DatabaseManager() = 0;
            virtual std::shared_ptr<av::istream_manager> StreamManager() = 0;

        private:
            std::vector<std::shared_ptr<spdlog::logger>> loggers;

            ServiceInfoObject<ServerInfo> serverInfo;
            ServiceInfoObject<DatabaseInfo> dbInfo;
            ServiceInfoObject<std::vector<StorageInfo>> storageInfo;


    };


} }
