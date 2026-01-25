
#include "db/io/event_repository.h"

bool iar::sql::EventRepository::create_table(soci::session& session)
{
    std::stringstream ss;
    ss << "CREATE TABLE " << tablename();
    ss << R"(
        (
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

    try {
        session << ss.str();
        return true;
    } catch(soci::soci_error const & e)
    {
        //std::cout << "Failed to create table!\n";
    }
    return false;
}

void iar::sql::EventRepository::drop_table(soci::session& session)
{
    session << "DROP TABLE " << tablename();
}

std::vector<iar::sql::Event> iar::sql::EventRepository::select_all()
{
    std::vector<iar::sql::Event> cams;

    return cams;
}
