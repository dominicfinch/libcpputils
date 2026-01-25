#pragma once

#include "../models/stream.h"
#include "../entity.h"

#include <functional>
#include <optional>
#include <vector>

namespace iar { namespace sql {

    class DatabaseManager;

    class StreamRepository: public IEntity<Stream>
    {
        public:
            StreamRepository(): IEntity<Stream>("streams") {}
            ~StreamRepository() = default;

            bool create_table(soci::session& session) override;
            void drop_table(soci::session& session) override;

            std::vector<Stream> select_all();
    };
}}