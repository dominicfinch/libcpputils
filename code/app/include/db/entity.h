#pragma once

#include <soci/session.h>
#include <string>

namespace iar { namespace sql {

    template <typename TableObject>
    class IEntity
    {
        public:
            using Traits = EntityTraits<TableObject>;

            IEntity(const std::string& tbname): _tablename(tbname) {}
            virtual ~IEntity() {}

            virtual void insert(soci::session& session, const TableObject& obj)
            {
                session << Traits::insert_sql, soci::use(obj);
            }

            virtual void update(soci::session& session, const TableObject& obj)
            {
                session << Traits::update_sql, soci::use(obj);
            }

            virtual void remove(soci::session& session, const std::string& id)
            {
                session << Traits::delete_sql, soci::use(id, "id");
            }

            std::vector<TableObject> select_all(soci::session& session)
            {
                std::vector<TableObject> result;
                soci::rowset<TableObject> rs = (session.prepare << Traits::select_all_sql);
                
                for (auto& row : rs)
                {
                    result.push_back(row);
                }
                return result;
            }

            virtual bool create_table(soci::session& session) { return false; }
            virtual void drop_table(soci::session& session) {}

            const std::string& tablename() { return _tablename; }

        private:
            const std::string _tablename;
    };



}}
