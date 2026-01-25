
#include "db/io/recording_repository.h"

bool iar::sql::RecordingRepository::create_table(soci::session& session)
{
    std::stringstream ss;
    ss << "CREATE TABLE " << tablename();
    ss << R"(
        (
            id              UUID PRIMARY KEY,
            stream_id       UUID NOT NULL REFERENCES streams(id),
            storage_id      UUID NOT NULL,
            start_time      TIMESTAMPTZ NOT NULL,
            end_time        TIMESTAMPTZ,
            status          TEXT NOT NULL, -- recording / completed / failed
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE INDEX idx_recordings_stream_id ON recordings(stream_id);
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

void iar::sql::RecordingRepository::drop_table(soci::session& session)
{
    session << "DROP TABLE " << tablename();
}

std::vector<iar::sql::Recording> iar::sql::RecordingRepository::select_all()
{
    std::vector<iar::sql::Recording> cams;

    return cams;
}
