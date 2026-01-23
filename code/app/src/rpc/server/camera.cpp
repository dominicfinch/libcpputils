
#include "rpc/server/camera.h"

grpc::Status iar::app::CameraService::GetCameraInfo(grpc::ServerContext * context, const iar::rpc::CameraId * request, iar::rpc::CameraInfo * response)
{
    
    return grpc::Status::OK;
}

grpc::Status iar::app::CameraService::SendPTZCommand(grpc::ServerContext* context, const iar::rpc::PTZCommand* request, iar::rpc::CommandResponse* response)
{
    
    return grpc::Status::OK;
}

grpc::Status iar::app::CameraService::UpdateVideoConfig(grpc::ServerContext* context, const iar::rpc::VideoConfig* request, iar::rpc::CommandResponse* response)
{
    
    return grpc::Status::OK;
}

grpc::Status iar::app::CameraService::ToggleFeatures(grpc::ServerContext* context, const iar::rpc::FeatureToggle* request, iar::rpc::CommandResponse* response)
{
    
    return grpc::Status::OK;
}