#pragma once

#include <string>
#include <chrono>
#include <optional>

#include <soci/soci.h>
#include <soci/values.h>
#include <soci/type-conversion.h>
#include "_traits.h"

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

    template<>
    struct EntityTraits<Camera> {
        static constexpr const char* table_name = "ss_cameras";

        static constexpr const char* insert_sql =
            "INSERT INTO ss_cameras (id, name, rtsp_url, capabilities, model, manufacturer, location, enabled) "
            "VALUES (:id, :name, :rtsp_url, :capabilities, :model, :manufacturer, :location, :enabled)";

        static constexpr const char* update_sql = "UPDATE ss_cameras SET \
                name=:name, rtsp_url=:rtsp_url,       \
                capabilities=:capabilities,           \
                model=:model, manufacturer=:manufacturer,   \
                location=:location, enabled=:enabled        \
            WHERE id=:id";

        static constexpr const char* select_all_sql =
            "SELECT id, name, rtsp_url, model, manufacturer, location, capabilities, enabled FROM ss_cameras";

        static constexpr const char* delete_sql =
            "DELETE FROM ss_cameras WHERE id=:id";
    };


} }


namespace soci {

    template<>
    struct type_conversion<iar::sql::Camera> {
        typedef values base_type;

        static void from_base(
            const values& v,
            indicator /*ind*/,
            iar::sql::Camera& cam) {

            cam.id       = v.get<std::string>("id");
            cam.name     = v.get<std::string>("name");
            cam.rtsp_url = v.get<std::string>("rtsp_url");
            cam.capabilities_json     = v.get<std::string>("capabilities");
            cam.model     = v.get<std::string>("model");
            cam.manufacturer     = v.get<std::string>("manufacturer");
            cam.location     = v.get<std::string>("location");
            cam.enabled     = v.get<int>("enabled");
        }

        static void to_base(const iar::sql::Camera& cam, values& v, indicator& ind)
        {
            v.set("id", cam.id);
            v.set("name", cam.name);
            v.set("rtsp_url", cam.rtsp_url);
            v.set("capabilities", cam.capabilities_json);
            v.set("model", cam.model);
            v.set("manufacturer", cam.manufacturer);
            v.set("location", cam.location);
            v.set("enabled", (int)cam.enabled);
            ind = i_ok;
        }
    };

} // namespace soci
