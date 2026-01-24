
#include "db/io/camera_repository.h"

bool iar::sql::CameraRepository::create_table(soci::session& session)
{
    session << R"(
        CREATE TABLE cameras (
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
    return true;
}

void iar::sql::CameraRepository::drop_table(soci::session& session)
{
    session << "DROP TABLE cameras;";
}

std::vector<iar::sql::Camera> iar::sql::CameraRepository::select_all()
{
    std::vector<iar::sql::Camera> cams;

    return cams;
}
