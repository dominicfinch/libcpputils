#include "database.h"

// Singleton instance
iar::app::DatabaseManager& iar::app::DatabaseManager::instance() {
    static DatabaseManager instance;
    return instance;
}

void iar::app::DatabaseManager::initialize(const std::string& conn_str, size_t pool_size) {
    std::unique_lock<std::mutex> lock(poolMutex);
    connectionString = conn_str;
    poolSize = pool_size;

    for (size_t i = 0; i < pool_size; ++i) {
        try {
            auto conn = new pqxx::connection(connectionString);
            if (conn->is_open()) {
                pool.emplace(conn);
            } else {
                delete conn;
                throw std::runtime_error("Failed to open PostgreSQL connection");
            }
        } catch (const std::exception& e) {
            std::cerr << "DB init error: " << e.what() << std::endl;
        }
    }

    std::cout << "[DatabaseManager] Initialized " << pool.size() << " connections.\n";
}

iar::app::DatabaseManager::ConnectionPtr iar::app::DatabaseManager::getConnection() {
    std::unique_lock<std::mutex> lock(poolMutex);
    poolCond.wait(lock, [this] { return !pool.empty(); });

    ConnectionPtr conn = std::move(pool.front());
    pool.pop();
    return conn;
}

void iar::app::DatabaseManager::releaseConnection(ConnectionPtr conn) {
    std::unique_lock<std::mutex> lock(poolMutex);
    pool.push(std::move(conn));
    lock.unlock();
    poolCond.notify_one();
}

// ---------- CRUD operations ----------

void iar::app::DatabaseManager::addDevice(const std::string& user_id, const std::string& device_id, const std::string& public_key) {
    auto conn = getConnection();
    try {
        pqxx::work txn(*conn);
        txn.exec_params(
            "INSERT INTO devices (user_id, device_id, public_key) VALUES ($1, $2, $3) "
            "ON CONFLICT (device_id) DO UPDATE SET public_key = EXCLUDED.public_key;",
            user_id, device_id, public_key
        );
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "[DB] addDevice error: " << e.what() << std::endl;
    }
    releaseConnection(std::move(conn));
}

std::string iar::app::DatabaseManager::getDeviceKey(const std::string& device_id) {
    auto conn = getConnection();
    std::string key;
    try {
        pqxx::nontransaction txn(*conn);
        pqxx::result r = txn.exec_params("SELECT public_key FROM devices WHERE device_id = $1;", device_id);
        if (!r.empty()) key = r[0]["public_key"].c_str();
    } catch (const std::exception& e) {
        std::cerr << "[DB] getDeviceKey error: " << e.what() << std::endl;
    }
    releaseConnection(std::move(conn));
    return key;
}

void iar::app::DatabaseManager::saveMessage(const std::string& sender, const std::string& recipient, const std::string& ciphertext) {
    auto conn = getConnection();
    try {
        pqxx::work txn(*conn);
        txn.exec_params(
            "INSERT INTO messages (sender_device, recipient_device, ciphertext) VALUES ($1, $2, $3);",
            sender, recipient, ciphertext
        );
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "[DB] saveMessage error: " << e.what() << std::endl;
    }
    releaseConnection(std::move(conn));
}

pqxx::result iar::app::DatabaseManager::fetchMessages(const std::string& recipient) {
    auto conn = getConnection();
    pqxx::result r;
    try {
        pqxx::nontransaction txn(*conn);
        r = txn.exec_params(
            "SELECT sender_device, ciphertext, timestamp FROM messages WHERE recipient_device = $1 ORDER BY timestamp ASC;",
            recipient
        );
    } catch (const std::exception& e) {
        std::cerr << "[DB] fetchMessages error: " << e.what() << std::endl;
    }
    releaseConnection(std::move(conn));
    return r;
}
