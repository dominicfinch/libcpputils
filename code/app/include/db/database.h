/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include "interfaces/db.h"
#include <string>
#include <mutex>
#include <soci/connection-pool.h>
#include <soci/session.h>

#include "io/camera_repository.h"
#include "io/event_repository.h"
#include "io/recording_repository.h"
#include "io/storage_location_repository.h"
#include "io/stream_repository.h"
#include "io/video_object_repository.h"

namespace iar { namespace sql {

    class DatabaseManager: public idatabase_manager
    {
    public:
        enum class Backend {
            Postgres,
            MySQL,
            SQLite
        };

        struct Config {
            Backend backend;
            std::string connection_string;
            size_t connection_pool_size = 4;
        };

        DatabaseManager() = default;
        ~DatabaseManager()
        {
            
        }

        soci::session& session();
        const Config& config() { return config_; }

        soci::connection_pool& pool();
        bool initialize_connection_pool(const Config& config);
        void create_schema(bool drop_first=false);

        CameraRepository& getCameraTable() { return _cameraRepository; }
        EventRepository& getEventTable() { return _eventRepository; }
        RecordingRepository& getRecordingTable() { return _recordingRepository; }
        StreamRepository& getStreamTable() { return _streamRepository; }


    private:
        
        Config config_;
        std::unique_ptr<soci::connection_pool> pool_;
        std::vector<std::mutex> session_locks_;
        bool connected_ = false;

        CameraRepository _cameraRepository;
        EventRepository _eventRepository;
        RecordingRepository _recordingRepository;
        StreamRepository _streamRepository;
    };

}}
