#pragma once

#include <string>
#include <functional>
#include <memory>

namespace iar { namespace app {

    enum class FingerprintResult {
        Success,
        Error,
        Match,
        NoMatch,
        NoDevice,
        NotSupported
    };

    struct EnrollProgress {
        // completed stages (1..n) and total stages
        int completed;
        int total;
        std::string message; // optional textual message (may be empty)
    };

    class FingerprintReader {
    public:
        FingerprintReader();
        ~FingerprintReader();

        // Initialize the library/device. Returns true on success.
        bool initialize();

        // Shutdown and release device.
        void shutdown();

        // Synchronous convenience wrappers (blocking). Use only if you prefer sync behavior.
        FingerprintResult enroll_sync(const std::string &userId);   // will block
        FingerprintResult verify_sync(const std::string &userId);   // will block

        // Asynchronous API with callbacks:
        // progress_cb: called repeatedly during enrollment with stages completed/total.
        // finished_cb: called once when finished: (result, optional textual error)
        //
        // NOTE: libfprint async callbacks require libfprint events to be handled.
        // Either run a GLib main loop or call fp_handle_events()/fp_handle_events_timeout() periodically.
        void enroll_async(const std::string &userId,
                        std::function<void(const EnrollProgress&)> progress_cb,
                        std::function<void(FingerprintResult, const std::string& /*err*/)> finished_cb);

        // verify_async: finished_cb called with Match/NoMatch/Error.
        void verify_async(const std::string &userId,
                        std::function<void(FingerprintResult, const std::string& /*err*/)> finished_cb);

    private:
        struct Impl;
        Impl* impl;
    };

}}