#pragma once

#include "../models/recording.h"
#include "../entity.h"

#include <functional>
#include <optional>
#include <vector>

namespace iar { namespace sql {

    class DatabaseManager;

    class RecordingRepository: public IEntity<Recording>
    {
        public:
            RecordingRepository() = default;
            ~RecordingRepository() = default;

            bool create_table(soci::session& session) override;
            void drop_table(soci::session& session) override;

            std::vector<Recording> select_all();
    };
}}