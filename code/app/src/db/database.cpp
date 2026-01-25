/*
 © Copyright 2025 Dominic Finch
*/

#include "db/database.h"

#include <soci/postgresql/soci-postgresql.h>
//#include <soci/mysql/soci-mysql.h>
//#include <soci/sqlite3/soci-sqlite3.h>

#include "uuid.h"

bool iar::sql::DatabaseManager::initialize_connection_pool(const Config& config)
{
    config_ = config;
    pool_ = std::make_unique<soci::connection_pool>(config.connection_pool_size);

    auto connection_count = 0;
    for (size_t i = 0; i < config_.connection_pool_size; ++i)
    {
        soci::session& sql = pool_->at(i);

        switch (config_.backend)
        {
            case Backend::Postgres:
                sql.open(soci::postgresql, config_.connection_string);
                connection_count++;
                break;
                /*
            case Backend::MySQL:
                sql.open(soci::mysql, config_.connection_string);
                break;
            case Backend::SQLite:
                sql.open(soci::sqlite3, config_.connection_string);
                break;
                */
        }
    }

    connected_ = connection_count == config_.connection_pool_size;
    return connected_;
}

soci::session& iar::sql::DatabaseManager::session()
{
    // Simple approach: grab first session
    //for(auto i=0; i<config_.connection_pool_size; i++)
    //{
        
    //}
    return pool_->at(0);    // TODO: Need to improve this. Ideally would have a 'checkout-checkin' model (so can properly mutex lock a given session for a set of queries).
}

soci::connection_pool& iar::sql::DatabaseManager::pool() {
    return *pool_;
}


void iar::sql::DatabaseManager::create_schema()
{
    if(connected_)
    {
        auto expected_table_count = 4, success_count = 0;

        // Note: Be careful with order. Some tables depend on others (e.g. for indexes).
        success_count += _cameraRepository.create_table(session()) ? 1 : 0;
        success_count += _streamRepository.create_table(session()) ? 1 : 0;
        success_count += _recordingRepository.create_table(session()) ? 1 : 0;
        success_count += _eventRepository.create_table(session()) ? 1 : 0;

        Camera camera;
        camera.id = utils::generate_uuid();
        camera.enabled = true;
        camera.location = "testing";
        camera.manufacturer = "HIKVision";
        camera.model = "dummy-model";
        camera.name = "dummy-camera";
        camera.rtsp_url = "rtps://...";
        camera.capabilities_json = "{}";

        getCameraTable().insert(session(), camera);

        if(success_count != expected_table_count)
        {
            // TODO
        }
    }
}