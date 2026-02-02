#pragma once

#include "node.h"
#include <assert.h>

namespace iar { namespace rpc {

    class irpc_service
    {
        public:
            irpc_service(app::security_service_context * ssc) : _container_ctx(ssc) { assert(ssc != nullptr); }

            const app::security_service_context * Container() { return _container_ctx; }

        private:
            app::security_service_context * _container_ctx = nullptr;

    };


}}