#pragma once

#include <string>

namespace iar { namespace app {

    // Simple result enum
    enum class FingerprintResult {
        Success,
        NoDevice,
        NotSupported,
        Match,
        NoMatch,
        Error
    };

    class FingerprintReader {
    public:
        FingerprintReader();
        ~FingerprintReader();

        bool initialize();
        void shutdown();

        FingerprintResult enroll(const std::string& userId);
        FingerprintResult verify(const std::string& userId);

    private:
        struct Impl;
        Impl* impl;
    };

}}