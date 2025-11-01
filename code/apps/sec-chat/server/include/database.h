#pragma once

#include <pqxx/pqxx>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <string>
#include <memory>
#include <iostream>

namespace iar { namespace app {

class DatabaseManager {
public:
    // Singleton accessor
    static DatabaseManager& instance();

    // Initialize pool (call this once at startup)
    void initialize(const std::string& conn_str, size_t pool_size = 4);

    // Simple CRUD convenience wrappers
    void addDevice(const std::string& user_id, const std::string& device_id, const std::string& public_key);
    std::string getDeviceKey(const std::string& device_id);
    void saveMessage(const std::string& sender, const std::string& recipient, const std::string& ciphertext);
    pqxx::result fetchMessages(const std::string& recipient);

private:
    DatabaseManager() = default;
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    // Connection pool internals
    struct ConnectionDeleter {
        void operator()(pqxx::connection* c) const noexcept {
            if (c && c->is_open()) {
                try { c->close(); } catch (...) {}
            }
            delete c;
        }
    };

    using ConnectionPtr = std::unique_ptr<pqxx::connection, ConnectionDeleter>;

    ConnectionPtr getConnection();
    void releaseConnection(ConnectionPtr conn);

    std::string connectionString;
    std::queue<ConnectionPtr> pool;
    std::mutex poolMutex;
    std::condition_variable poolCond;
    size_t poolSize = 0;
};

}}