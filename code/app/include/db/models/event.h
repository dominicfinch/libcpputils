
#pragma once

#include <string>
#include <chrono>
#include <optional>

#include <soci/values.h>
#include <soci/type-conversion.h>

namespace iar { namespace sql {
    
    struct Event {
        std::string id;
        std::string stream_id;
        std::string camera_id;
        std::string type;
        std::string payload_json;
        //std::chrono::system_clock::time_point created_at;
    };


    
} }

namespace soci {

template<>
struct type_conversion<iar::sql::Event> {
    typedef values base_type;

    static void from_base(const values& v, indicator, iar::sql::Event& u)
    {
        u.id = v.get<std::string>("id");
        // TODO
        //u.created_at = v.get<std::chrono::time_point>("created_at");
    }

    static void to_base(const iar::sql::Event& u, values& v, indicator& ind)
    {
        v.set("id", u.id);
        //v.set("name", u.name);
        // TODO
        //v.set("created_at", std::chrono::system_clock().now());
        ind = i_ok;
    }
};

}