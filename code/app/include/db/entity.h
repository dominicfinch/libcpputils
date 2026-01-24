#pragma once

#include <soci/session.h>

namespace iar { namespace sql {

    template <typename TableObject>
    class IEntity
    {
        public:
            virtual void insert(soci::session& session, const TableObject& tb)
            {
                //session << tb;
            }

            virtual void update(soci::session& session, const TableObject& tb)
            {
                //session << tb;
            }

            virtual void remove(soci::session& session, const std::string& tb_id)
            {
                //session << tb;
            }

            virtual bool create_table(soci::session& session) { return false; }
            virtual void drop_table(soci::session& session) {}
    };



}}
