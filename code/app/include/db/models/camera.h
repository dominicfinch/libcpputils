#pragma once

#include <string>
#include <chrono>
#include <optional>

#include <soci/values.h>
#include <soci/type-conversion.h>

namespace iar { namespace sql {
    
    struct Camera {
        std::string id;
        std::string name;
        std::string manufacturer;
        std::string model;
        std::string rtsp_url;
        std::string capabilities_json;
        //std::chrono::system_clock::time_point created_at;
        std::string location;
        bool enabled;
    };



} }

namespace soci {

template<>
struct type_conversion<iar::sql::Camera> {
    typedef values base_type;

    static void from_base(const values& v, indicator, iar::sql::Camera& u)
    {
        u.id = v.get<std::string>("id");
        // TODO
        //u.created_at = v.get<std::chrono::time_point>("created_at");
    }

    static void to_base(const iar::sql::Camera& u, values& v, indicator& ind)
    {
        v.set("id", u.id);
        v.set("name", u.name);
        // TODO
        //v.set("created_at", std::chrono::system_clock().now());
        ind = i_ok;
    }
};

}