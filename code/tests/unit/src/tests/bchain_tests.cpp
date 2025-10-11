
#include "bchain_tests.h"
#include "bchain.h"
#include <string>

bool test_blockchain_serialize_roundtrip() {
    iar::utils::Blockchain<std::string> chain;
    chain.add_block("Genesis");
    auto genesis = chain.find_block([](const auto& b) { return b.data == "Genesis"; });
    if (!genesis.has_value()) return false;

    chain.add_block("Child", {genesis.value()->id});

    // Serialize to string
    Json::Value root;
    for (const auto& id : {"Genesis", "Child"}) {
        auto block = chain.find_block([&](const auto& b) { return b.data == id; });
        if (!block.has_value()) return false;
    }

    std::stringstream buffer;
    {
        std::ofstream tmp_out("test_chain.json");
        if (!chain.save_to_file("test_chain.json")) return false;
    }

    iar::utils::Blockchain<std::string> restored;
    if (!restored.load_from_file("test_chain.json")) return false;

    auto b1 = restored.find_block([](const auto& b) { return b.data == "Genesis"; });
    auto b2 = restored.find_block([](const auto& b) { return b.data == "Child"; });

    return b1.has_value() && b2.has_value();
}

bool test_blockchain_save_load_jsoncpp() {
    iar::utils::Blockchain<std::string> chain;
    chain.add_block("Genesis");

    auto genesis = chain.find_block([](const auto& b) { return b.data == "Genesis"; });
    if (!genesis.has_value()) return false;

    chain.add_block("Block 2", {genesis.value()->id});
    std::string filename = "test_blockchain.json";

    if (!chain.save_to_file(filename)) return false;

    iar::utils::Blockchain<std::string> loaded;
    if (!loaded.load_from_file(filename)) return false;

    auto g = loaded.find_block([](const auto& b) { return b.data == "Genesis"; });
    auto b2 = loaded.find_block([](const auto& b) { return b.data == "Block 2"; });

    // Clean up
    std::remove(filename.c_str());

    return g.has_value() && b2.has_value();
}