
#include "db/io/camera_repository.h"
#include <soci/error.h>
#include <iostream>

bool iar::sql::CameraRepository::create_table(soci::session& session)
{
    std::stringstream ss;
    ss << "CREATE TABLE " << tablename();
    ss << R"(
        (
            id              UUID PRIMARY KEY,
            name            TEXT NOT NULL,
            manufacturer    TEXT,
            model           TEXT,
            rtsp_url        TEXT NOT NULL,
            capabilities    JSONB,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            location        TEXT,
            enabled         BOOL
        );
    )";
    
    try {
        session << ss.str();
        return true;
    } catch(soci::soci_error const & e)
    {
        std::cout << "Failed to create table!\n";
    }
    return false;
}

void iar::sql::CameraRepository::drop_table(soci::session& session)
{
    session << "DROP TABLE " << tablename();
}

std::vector<iar::sql::Camera> iar::sql::CameraRepository::select_all()
{
    std::vector<iar::sql::Camera> cams;

    return cams;
}
