
#include "db/io/stream_repository.h"

bool iar::sql::StreamRepository::create_table(soci::session& session)
{
    session << R"(
        CREATE TABLE streams (
            id              UUID PRIMARY KEY,
            camera_id       UUID NOT NULL REFERENCES cameras(id),
            protocol        TEXT NOT NULL, -- rtsp / rtsps
            source_url      TEXT NOT NULL,
            status          TEXT NOT NULL, -- active / stopped / error
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE INDEX idx_streams_camera_id ON streams(camera_id);
    )";
    return true;
}

void iar::sql::StreamRepository::drop_table(soci::session& session)
{

}

std::vector<iar::sql::Stream> iar::sql::StreamRepository::select_all()
{
    std::vector<iar::sql::Stream> cams;

    return cams;
}
