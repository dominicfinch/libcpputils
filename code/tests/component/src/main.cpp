#include <iostream>
#include <vector>
#include <functional>
#include <string>
#include <stdexcept>
#include <chrono>

// Simple color helper for console output
namespace Color {
    const std::string RESET  = "\033[0m";
    const std::string GREEN  = "\033[32m";
    const std::string RED    = "\033[31m";
    const std::string CYAN   = "\033[36m";
    const std::string YELLOW = "\033[33m";
}

// Basic assertion macro
#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            throw std::runtime_error(std::string("Assertion failed: ") + #expr + \
                                     " (in " + __FUNCTION__ + ")"); \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if (!((a) == (b))) { \
            throw std::runtime_error(std::string("Assertion failed: ") + \
                                     #a + " == " + #b + " (got: " + std::to_string(a) + \
                                     " != " + std::to_string(b) + ")"); \
        } \
    } while (0)

// --------------------------------------------------------------------
// Generic Test Runner
// --------------------------------------------------------------------
class TestRunner {
public:
    using TestSet = std::pair<std::string, std::function<void()>>;

    void addTestSet(const std::string& name, std::function<void()> func) {
        testSets.emplace_back(name, func);
    }

    int runAll() {
        using namespace std::chrono;
        int totalPassed = 0, totalFailed = 0;

        std::cout << "\n🚀 Starting Component Test Runner (" 
                  << testSets.size() << " test sets)\n";

        for (auto& [name, func] : testSets) {
            std::cout << "\n" << Color::CYAN << "▶ Test Set: " << name 
                      << Color::RESET << "\n-----------------------------------\n";

            int passed = 0, failed = 0;
            auto start = high_resolution_clock::now();

            try {
                func(); // run the lambda that calls test_XXX functions
                passed++;
            } catch (const std::exception& e) {
                failed++;
                std::cerr << Color::RED << "❌ Test set failed: " 
                          << e.what() << Color::RESET << "\n";
            } catch (...) {
                failed++;
                std::cerr << Color::RED << "❌ Test set threw unknown exception!" 
                          << Color::RESET << "\n";
            }

            auto end = high_resolution_clock::now();
            auto duration = duration_cast<milliseconds>(end - start).count();

            if (failed == 0)
                std::cout << Color::GREEN << "✅ " << name << " passed in "
                          << duration << " ms\n" << Color::RESET;
            else
                std::cout << Color::RED << "❌ " << name << " failed in "
                          << duration << " ms\n" << Color::RESET;

            totalPassed += passed;
            totalFailed += failed;
        }

        std::cout << "\n-----------------------------------\n";
        std::cout << "Summary: " << Color::GREEN << totalPassed << " passed" 
                  << Color::RESET << ", " << Color::RED << totalFailed << " failed"
                  << Color::RESET << "\n";

        return totalFailed;
    }

private:
    std::vector<TestSet> testSets;
};

// --------------------------------------------------------------------
// Example Tests
// --------------------------------------------------------------------

// These could be in different files in practice
void test_registerDevice() {
    std::cout << "Running test_registerDevice...\n";
    ASSERT_TRUE(true); // pretend we called the RPC and validated JSON
}

void test_sendMessage() {
    std::cout << "Running test_sendMessage...\n";
    ASSERT_EQ(5, 5);
}

void test_dbConnection() {
    std::cout << "Running test_dbConnection...\n";
    // Simulate a failing case
    ASSERT_TRUE(false && "Database not reachable");
}

// --------------------------------------------------------------------
// Main Runner
// --------------------------------------------------------------------
int main() {
    TestRunner runner;

    runner.addTestSet("RPC Tests", []() {
        test_registerDevice();
        test_sendMessage();
    });

    runner.addTestSet("Database Tests", []() {
        test_dbConnection();
    });

    return runner.runAll();
}
