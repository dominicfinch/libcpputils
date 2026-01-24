
#include "db/io/event_repository.h"

bool iar::sql::EventRepository::create_table(soci::session& session)
{
    session << R"(
        CREATE TABLE events (
            id              UUID PRIMARY KEY,
            stream_id       UUID,
            camera_id       UUID,
            type            TEXT NOT NULL, -- RECORDING_STARTED, ERROR, MOTION
            payload         JSONB,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE INDEX idx_events_stream_id ON events(stream_id);
        CREATE INDEX idx_events_camera_id ON events(camera_id);
    )";
    return true;
}

void iar::sql::EventRepository::drop_table(soci::session& session)
{

}

std::vector<iar::sql::Event> iar::sql::EventRepository::select_all()
{
    std::vector<iar::sql::Event> cams;

    return cams;
}
