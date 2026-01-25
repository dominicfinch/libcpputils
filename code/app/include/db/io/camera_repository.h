#pragma once

#include "../models/camera.h"
#include "../entity.h"

#include <functional>
#include <optional>
#include <vector>

namespace iar { namespace sql {

    class DatabaseManager;

    class CameraRepository: public IEntity<Camera>
    {
        public:
            CameraRepository(): IEntity<Camera>("cameras") {}
            ~CameraRepository() = default;

            bool create_table(soci::session& session) override;
            void drop_table(soci::session& session) override;



            //std::optional<Camera> find_by_id(const std::string& camera_id);
            //std::vector<Camera> find_by(std::function<bool(const Camera& cam)> condition);
            
            std::vector<Camera> select_all();
    };
}}