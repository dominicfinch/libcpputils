
#include "fingerprint.h"
#include <iostream>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <winbio.h>
#elif defined(__linux__)
#include <fprint.h>
#include <glib.h>
#endif
#include <vector>

namespace iar::app {

struct FingerprintReader::Impl {
#ifdef _WIN32
    WINBIO_SESSION_HANDLE session = nullptr;
#elif defined(__linux__)
    FpContext* context = nullptr;
    FpDevice* dev = nullptr;
    bool initialized = false;
#endif
};

// ------------------------ Constructor / Destructor ------------------------
FingerprintReader::FingerprintReader() : impl(new Impl()) {}
FingerprintReader::~FingerprintReader() { shutdown(); delete impl; }

// ------------------------ Initialize ------------------------
bool FingerprintReader::initialize() {
#ifdef _WIN32
    HRESULT hr = WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,
        WINBIO_POOL_SYSTEM,
        WINBIO_FLAG_DEFAULT,
        nullptr, 0,
        nullptr,
        &impl->session
    );
    return SUCCEEDED(hr);

#elif defined(__linux__)
    impl->context = fp_context_new();
    if (!impl->context) {
        std::cerr << "Failed to create FpContext\n";
        return false;
    }

    fp_context_enumerate(impl->context);
    GPtrArray* devices = fp_context_get_devices(impl->context);
    if (!devices || devices->len == 0) {
        std::cerr << "No fingerprint devices found\n";
        return false;
    }

    impl->dev = static_cast<FpDevice*>(devices->pdata[0]); // use first device
    if (!impl->dev) return false;

    if (!fp_device_open_sync(impl->dev, nullptr, nullptr)) {
        std::cerr << "Failed to open device\n";
        return false;
    }

    impl->initialized = true;
    return true;
#endif
}

// ------------------------ Shutdown ------------------------
void FingerprintReader::shutdown() {
#ifdef _WIN32
    if (impl->session) {
        WinBioCloseSession(impl->session);
        impl->session = nullptr;
    }
#elif defined(__linux__)
    if (impl->dev) {
        fp_device_close_sync(impl->dev, nullptr, nullptr);
        impl->dev = nullptr;
    }
    impl->initialized = false;
#endif
}

// ------------------------ Enrollment ------------------------
FingerprintResult FingerprintReader::enroll(const std::string& userId) {
#ifdef _WIN32
    return FingerprintResult::NotSupported;
#elif defined(__linux__)
    if (!impl->initialized) return FingerprintResult::NoDevice;

    FpPrint* print = fp_device_enroll_sync(impl->dev, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!print) return FingerprintResult::Error;

    // Serialize print
    gsize size = 0;
    gboolean data = fp_print_serialize(print, nullptr, nullptr, nullptr);
    g_object_unref(print);
    if (!data) return FingerprintResult::Error;

    // Save to file
    std::ofstream f(userId + ".fp", std::ios::binary);
    if (!f.is_open()) {
        //g_free(data);
        return FingerprintResult::Error;
    }
    f.write(reinterpret_cast<char*>(data), size);
    //g_free(data);
    return FingerprintResult::Success;
#endif
}

// ------------------------ Verification ------------------------
FingerprintResult FingerprintReader::verify(const std::string& userId) {
#ifdef _WIN32
    return FingerprintResult::NotSupported;
#elif defined(__linux__)
    if (!impl->initialized) return FingerprintResult::NoDevice;

    // Load serialized print
    std::ifstream f(userId + ".fp", std::ios::binary | std::ios::ate);
    if (!f.is_open()) return FingerprintResult::Error;

    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if (!f.read(buffer.data(), size)) return FingerprintResult::Error;

    FpPrint* stored = fp_print_deserialize(reinterpret_cast<const guchar*>(buffer.data()), size, nullptr);
    if (!stored) return FingerprintResult::Error;

    bool match = fp_device_verify_sync(impl->dev, stored, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    g_object_unref(stored);
    return match ? FingerprintResult::Match : FingerprintResult::NoMatch;
#endif
}

} // namespace iar::app