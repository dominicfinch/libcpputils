
#include "db/io/recording_repository.h"

bool iar::sql::RecordingRepository::create_table(soci::session& session)
{
    session << R"(
        CREATE TABLE recordings (
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
    return true;
}

void iar::sql::RecordingRepository::drop_table(soci::session& session)
{

}

std::vector<iar::sql::Recording> iar::sql::RecordingRepository::select_all()
{
    std::vector<iar::sql::Recording> cams;

    return cams;
}
