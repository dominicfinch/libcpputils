
#pragma once

#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <optional>
#include <string>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <json/json.h>

#include "base64.h"
#include "hash.h"
#include "hex.h"

namespace iar {
    namespace utils {

        template <typename T>
        class Blockchain {
        public:
            struct Block {
                std::string id;
                T data;
                std::vector<std::string> parent_ids;
                std::chrono::system_clock::time_point timestamp;

                Block() = default;
                Block(const std::string& id, const T& data,
                    const std::vector<std::string>& parents)
                    : id(id), data(data), parent_ids(parents),
                    timestamp(std::chrono::system_clock::now()) {}
            };

            using HashFunction = std::function<std::string(const T&, const std::vector<std::string>&)>;

            Blockchain(HashFunction hash_fn = default_hash): hash_function(std::move(hash_fn)) {}

            bool add_block(const T& data, const std::vector<std::string>& parent_ids = {}) {
                std::string id = hash_function(data, parent_ids);
                if (blocks.find(id) != blocks.end())
                    return false;
                blocks[id] = std::make_unique<Block>(id, data, parent_ids);
                return true;
            }

            std::optional<const Block*> find_block(std::function<bool(const Block&)> predicate) const {
                for (const auto& [id, block] : blocks) {
                    if (predicate(*block)) return block.get();
                }
                return std::nullopt;
            }

            void set_hash_function(HashFunction fn) { hash_function = std::move(fn); }

            size_t size() const { return blocks.size(); }

            // -------------------------------
            //         Serialization
            // -------------------------------
            Json::Value serialize() const;
            std::string serialize(bool prettify = false);

            void deserialize(Json::Value& root);
            bool deserialize(const std::string& content);

            bool save_to_file(const std::string& path) const;
            bool load_from_file(const std::string& path);

        private:
            std::unordered_map<std::string, std::unique_ptr<Block>> blocks;
            HashFunction hash_function;

            // Simplified default hash function
            static std::string default_hash(const T& data, const std::vector<std::string>& parents) {
                std::hash<std::string> hasher;
                std::string combined = Json::writeString(Json::StreamWriterBuilder(), serialize_data(data));
                for (const auto& pid : parents) combined += pid;
                return std::to_string(hasher(combined));
            }

            // These two methods assume T is JSON-compatible
            static Json::Value serialize_data(const T& data) {
                Json::Value val;
                val = data; // This works for JSON-compatible types like std::string, int, etc.
                return val;
            }

            static T deserialize_data(const Json::Value& val) {
                return val.as<T>();
            }
        };

    }
}


template <typename T>
bool iar::utils::Blockchain<T>::save_to_file(const std::string& path) const {
    Json::Value root = serialize();

    std::ofstream ofs(path);
    if (!ofs) return false;

    Json::StreamWriterBuilder builder;
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->write(root, &ofs);
    return true;
}

template <typename T>
bool iar::utils::Blockchain<T>::load_from_file(const std::string& path)  {
    std::ifstream ifs(path);
    if (!ifs) return false;

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;

    if (!Json::parseFromStream(builder, ifs, &root, &errs)) {
        return false;
    }

    deserialize(root);

    return true;
}

template <typename T>
Json::Value iar::utils::Blockchain<T>::serialize() const {
    Json::Value root;
    for (auto& [id, block] : blocks) {
        Json::Value json_block;
        json_block["id"] = block->id;
        json_block["data"] = serialize_data(block->data);
        for (const auto& pid : block->parent_ids) {
            json_block["parent_ids"].append(pid);
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    block->timestamp.time_since_epoch()).count();
        json_block["timestamp"] = static_cast<Json::Int64>(ms);

        root["blocks"].append(json_block);
    }
    return root;
}

template <typename T>
void iar::utils::Blockchain<T>::deserialize(Json::Value& root) {
    blocks.clear();

    for (auto& json_block : root["blocks"]) {
        Block block;
        block.id = json_block["id"].asString();
        block.data = deserialize_data(json_block["data"]);

        for (const auto& pid : json_block["parent_ids"]) {
            block.parent_ids.push_back(pid.asString());
        }

        block.timestamp = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(json_block["timestamp"].asInt64()));
        blocks[block.id] = std::make_unique<Block>(block);
    }
}

template <typename T>
std::string iar::utils::Blockchain<T>::serialize(bool prettify) {
    Json::Value root = serialize();

    Json::StreamWriterBuilder wbuilder;
    if(prettify)
        wbuilder["indentation"] = "  ";

    return Json::writeString(wbuilder, root);
}

template <typename T>
bool iar::utils::Blockchain<T>::deserialize(const std::string& content) {
    Json::CharReaderBuilder rbuilder;
    std::unique_ptr<Json::CharReader> const reader(rbuilder.newCharReader());
    std::string errs;
    Json::Value object;

    auto parse_success = reader->parse(content.data(), content.data() + content.size(), &object, &errs);
    deserialize(object);

    return parse_success && !object.empty();
}