
#pragma once

#include <memory>
#include <grpc++/server.h>

namespace iar { namespace app {
    
    template <class service_settings>
    class security_service {
        public:
            virtual bool Initialize(service_settings& configuration) = 0;
            virtual bool Run() = 0;
            virtual void Shutdown() = 0;
            virtual std::unique_ptr<grpc::Server>& Server() = 0;
            virtual service_settings& Configuration() = 0;
    };
} }
