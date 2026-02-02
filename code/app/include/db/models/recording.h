
#pragma once

#include <soci/soci.h>
#include <string>
#include <chrono>
#include <optional>

#include <soci/soci.h>
#include <soci/values.h>
#include <soci/type-conversion.h>
#include "_traits.h"

namespace iar { namespace sql {
    
    struct Recording {
        std::string id;
        std::string stream_id;
        std::string storage_id;
        //std::chrono::system_clock::time_point start_time;
        //std::optional<std::chrono::system_clock::time_point> end_time;
        std::string status;
        //std::chrono::system_clock::time_point created_at;
    };
    
    template<>
    struct EntityTraits<Recording> {
        static constexpr const char* table_name = "ss_recordings";

        static constexpr const char* insert_sql =
            "INSERT INTO ss_recordings "
            "(id, stream_id, storage_id, start_time, end_time, status, created_at) "
            "VALUES "
            "(:id, :stream_id, :storage_id, :start_time, :end_time, :status, :created_at)";

        static constexpr const char* update_sql =
            "UPDATE ss_recordings SET "
            "stream_id=:stream_id, "
            "storage_id=:storage_id, "
            "start_time=:start_time, "
            "end_time=:end_time, "
            "status=:status "
            "WHERE id=:id";

        static constexpr const char* delete_sql =
            "DELETE FROM ss_recordings WHERE id=:id";

        static constexpr const char* select_all_sql =
            "SELECT id, stream_id, storage_id, start_time, end_time, status, created_at "
            "FROM ss_recordings";

        static constexpr const char* select_by_id_sql =
            "SELECT id, stream_id, storage_id, start_time, end_time, status, created_at "
            "FROM ss_recordings WHERE id=:id";
    };

} }


namespace soci {

    template<>
    struct type_conversion<iar::sql::Recording> {
        typedef values base_type;

        static void from_base(
            const values& v,
            indicator /*ind*/,
            iar::sql::Recording& r)
        {
            r.id          = v.get<std::string>("id");
            r.stream_id   = v.get<std::string>("stream_id");
            r.storage_id  = v.get<std::string>("storage_id");
            //r.start_time  = v.get<std::chrono::system_clock::time_point>("start_time");
            //r.status      = v.get<std::string>("status");
            //r.created_at  = v.get<std::chrono::system_clock::time_point>("created_at");

            // Optional end_time
            if (v.get_indicator("end_time") == i_null) 
            {
                //r.end_time.reset();
            } else {
                //r.end_time = v.get<std::chrono::system_clock::time_point>("end_time");
            }
        }

        static void to_base(
            const iar::sql::Recording& r,
            values& v,
            indicator& ind)
        {
            v.set("id", r.id);
            v.set("stream_id", r.stream_id);
            v.set("storage_id", r.storage_id);
            //v.set("start_time", r.start_time);
            v.set("status", r.status);
            //v.set("created_at", r.created_at);

            //if (r.end_time.has_value())
            //{
                //v.set("end_time", *r.end_time);
            //} else {
                v.set("end_time", 0);
            //}

            ind = i_ok;
        }
    };

} // namespace soci
