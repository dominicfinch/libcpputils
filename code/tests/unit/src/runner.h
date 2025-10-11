#pragma once

#include <string>
#include <map>
#include <functional>

namespace iar {

    struct test_set_results
    {
        public:
            std::string test_set_name;
            int test_set_count = 0;
            int tests_passed = 0;
            int tests_failed = 0;
    };

    class TestRunner
    {
        public:
            void add_test_set(const std::string& name, std::function<void(TestRunner * runner, iar::test_set_results& results)> testSet);

            void execute_test(iar::test_set_results& results, const std::string& name, bool (*test)(void));

            void run_tests();

            const std::map<std::string, test_set_results>& results() { return test_results; }

        private:

            void report_test(const std::string& name, bool result);
            
            std::map<std::string, std::function<void(TestRunner * runner, iar::test_set_results& results)>> test_fixtures;
            std::map<std::string, test_set_results> test_results;
    };
}