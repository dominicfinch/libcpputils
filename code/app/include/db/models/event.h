
#pragma once

#include <string>
#include <chrono>
#include <optional>

#include <soci/soci.h>
#include <soci/values.h>
#include <soci/type-conversion.h>
#include "_traits.h"

namespace iar { namespace sql {
    
    struct Event {
        std::string id;
        std::string stream_id;
        std::string camera_id;
        std::string type;
        std::string payload_json;
        //std::chrono::system_clock::time_point created_at;
    };

    template<>
    struct EntityTraits<Event> {
        static constexpr const char* table_name = "ss_events";

        static constexpr const char* insert_sql =
            "INSERT INTO ss_events "
            "(id, stream_id, camera_id, type, payload) "
            "VALUES "
            "(:id, :stream_id, :camera_id, :type, :payload)";

        static constexpr const char* update_sql =
            "UPDATE ss_events SET "
            "stream_id=:stream_id, "
            "camera_id=:camera_id, "
            "type=:type, "
            "payload=:payload "
            "WHERE id=:id";

        static constexpr const char* delete_sql =
            "DELETE FROM ss_events WHERE id=:id";

        static constexpr const char* select_all_sql =
            "SELECT id, stream_id, camera_id, type, payload "
            "FROM ss_events";

        static constexpr const char* select_by_id_sql =
            "SELECT id, stream_id, camera_id, type, payload "
            "FROM ss_events WHERE id=:id";
    };

    
} }

namespace soci {

    template<>
    struct type_conversion<iar::sql::Event> {
        typedef values base_type;

        static void from_base(
            const values& v,
            indicator /*ind*/,
            iar::sql::Event& e)
        {
            e.id           = v.get<std::string>("id");
            e.stream_id    = v.get<std::string>("stream_id");
            e.camera_id    = v.get<std::string>("camera_id");
            e.type         = v.get<std::string>("type");
            e.payload_json = v.get<std::string>("payload");
        }

        static void to_base(
            const iar::sql::Event& e,
            values& v,
            indicator& ind)
        {
            v.set("id", e.id);
            v.set("stream_id", e.stream_id);
            v.set("camera_id", e.camera_id);
            v.set("type", e.type);
            v.set("payload", e.payload_json);

            ind = i_ok;
        }
    };

} // namespace soci
