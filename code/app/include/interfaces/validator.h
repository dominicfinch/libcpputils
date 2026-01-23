
#pragma once

#include <string>
#include <functional>
#include <utility>

namespace iar { namespace app {

    template <class T>
    class object_validator {
    public:
        object_validator() = default;
        explicit object_validator(std::function<void(std::string, std::string, std::string)>& callback): _callback(callback) {}
        virtual ~object_validator() = default;

        virtual int validate(T& config) { return 0; }
        std::function<void(std::string, std::string, std::string)>& getCallback() { return _callback; }
        void setCallback(std::function<void(std::string, std::string, std::string)> callback) { _callback = std::move(callback); }
        void clearCallback() { _callback = [](const std::string&, const std::string&, const std::string&) {}; }

    private:
        std::function<void(std::string, std::string, std::string)> _callback = [](const std::string&, const std::string&, const std::string&) {};
    };

} }
