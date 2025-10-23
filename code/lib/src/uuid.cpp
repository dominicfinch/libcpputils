#include "uuid.h"

#ifdef _WIN32
#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")
#else 
#include <uuid/uuid.h>
#endif

std::string iar::utils::generate_uuid()
{
    #ifdef _WIN32
    // Windows version
    UUID uuid;
    UuidCreate(&uuid);
    RPC_CSTR str = nullptr;
    UuidToStringA(&uuid, &str);
    std::string result(reinterpret_cast<char*>(str));
    RpcStringFreeA(&str);
    return result;
#else
    // Linux / macOS version (libuuid)
    uuid_t uuid;
    char str[37];
    uuid_generate(uuid);
    uuid_unparse(uuid, str);
    return std::string(str);
#endif
}