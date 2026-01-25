#pragma once

#include <string>
#include <chrono>
#include <optional>

#include <soci/soci.h>
#include <soci/values.h>
#include <soci/type-conversion.h>
#include "_traits.h"

namespace iar { namespace sql {
    
    struct Stream {
        std::string id;
        std::string camera_id;
        std::string protocol;
        std::string source_url;
        std::string status;
        //std::chrono::system_clock::time_point created_at;
    };

    template<>
    struct EntityTraits<Stream> {
        static constexpr const char* table_name = "streams";

        static constexpr const char* insert_sql =
            "INSERT INTO streams "
            "(id, camera_id, protocol, source_url, status) "
            "VALUES "
            "(:id, :camera_id, :protocol, :source_url, :status)";

        static constexpr const char* update_sql =
            "UPDATE streams SET "
            "camera_id=:camera_id, "
            "protocol=:protocol, "
            "source_url=:source_url, "
            "status=:status "
            "WHERE id=:id";

        static constexpr const char* delete_sql =
            "DELETE FROM streams WHERE id=:id";

        static constexpr const char* select_all_sql =
            "SELECT id, camera_id, protocol, source_url, status "
            "FROM streams";

        static constexpr const char* select_by_id_sql =
            "SELECT id, camera_id, protocol, source_url, status "
            "FROM streams WHERE id=:id";
    };

} }

namespace soci {

    template<>
    struct type_conversion<iar::sql::Stream> {
        typedef values base_type;

        static void from_base(
            const values& v,
            indicator /*ind*/,
            iar::sql::Stream& s)
        {
            s.id         = v.get<std::string>("id");
            s.camera_id  = v.get<std::string>("camera_id");
            s.protocol   = v.get<std::string>("protocol");
            s.source_url = v.get<std::string>("source_url");
            s.status     = v.get<std::string>("status");
        }

        static void to_base(
            const iar::sql::Stream& s,
            values& v,
            indicator& ind)
        {
            v.set("id", s.id);
            v.set("camera_id", s.camera_id);
            v.set("protocol", s.protocol);
            v.set("source_url", s.source_url);
            v.set("status", s.status);

            ind = i_ok;
        }
    };

} // namespace soci
