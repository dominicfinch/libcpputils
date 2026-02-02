#pragma once

#include "interfaces/rpc.h"
#include <grpcpp/grpcpp.h>
#include "camera_control.grpc.pb.h"

namespace iar { namespace app {

    class CameraService final: public rpc::CameraControlService::Service, public rpc::irpc_service
    {
        public:

        CameraService(app::security_service_context * ssc): rpc::irpc_service(ssc)
        {

        }
        ~CameraService() override = default;


        grpc::Status GetCameraInfo(grpc::ServerContext * context, const iar::rpc::CameraId * request, iar::rpc::CameraInfo * response) override;
        
        grpc::Status SendPTZCommand(grpc::ServerContext* context, const iar::rpc::PTZCommand* request, iar::rpc::CommandResponse* response) override;

        grpc::Status UpdateVideoConfig(grpc::ServerContext* context, const iar::rpc::VideoConfig* request, iar::rpc::CommandResponse* response) override;

        grpc::Status ToggleFeatures(grpc::ServerContext* context, const iar::rpc::FeatureToggle* request, iar::rpc::CommandResponse* response) override;
    };

}}