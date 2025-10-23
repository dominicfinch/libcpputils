#include "server.h"

void iar::app::SecChatServer::open_channel(const Json::Value& request, Json::Value& response)
{

    response["output"] = "test!";
}

void iar::app::SecChatServer::close_channel(const Json::Value& request, Json::Value& response)
{

}

void iar::app::SecChatServer::view_contacts(const Json::Value& request, Json::Value& response)
{

}
