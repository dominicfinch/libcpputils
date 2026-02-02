
#include "db/io/stream_repository.h"
#include <iostream>

bool iar::sql::StreamRepository::create_table(soci::session& session)
{
    std::stringstream ss;
    ss << "CREATE TABLE " << Traits::table_name;
    ss << R"(
        (
            id              UUID PRIMARY KEY,
            camera_id       UUID NOT NULL REFERENCES ss_cameras(id),
            protocol        TEXT NOT NULL, -- rtsp / rtsps
            source_url      TEXT NOT NULL,
            status          TEXT NOT NULL, -- active / stopped / error
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE INDEX idx_streams_camera_id ON ss_streams(camera_id);
    )";

    try {
        session << ss.str();
        return true;
    } catch(soci::soci_error const & e)
    {
        std::cout << "Failed to create table!\n";
        std::cout << e.get_error_message() << "\n";
    }
    return false;
}

void iar::sql::StreamRepository::drop_table(soci::session& session)
{
    session << "DROP TABLE " << Traits::table_name;
}

std::vector<iar::sql::Stream> iar::sql::StreamRepository::select_all()
{
    std::vector<iar::sql::Stream> cams;

    return cams;
}
