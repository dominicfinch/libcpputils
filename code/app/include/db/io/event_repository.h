#pragma once

#include "../models/event.h"
#include "../entity.h"

#include <functional>
#include <optional>
#include <vector>

namespace iar { namespace sql {

    class DatabaseManager;

    class EventRepository: public IEntity<Event>
    {
        public:
            EventRepository() = default;
            ~EventRepository() = default;

            bool create_table(soci::session& session) override;
            void drop_table(soci::session& session) override;

            std::vector<Event> select_all();
    };
}}