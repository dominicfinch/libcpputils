
#include "runner.h"
#include <iostream>

namespace cpp {

    void print_test_results(const std::map<std::string, cpp::test_set_results>& results)
    {
        std::cout << "\nOverall Results:\n";
        int total_passed = 0, total_failed = 0, total_tests = 0;
        for(auto ts : results)
        {
            total_passed += ts.second.tests_passed;
            total_failed += ts.second.tests_failed;
            total_tests += ts.second.test_set_count;
            std::cout << " - " << ts.first << ": " << ts.second.tests_passed << "/" << ts.second.test_set_count << std::endl;
        }

        std::cout << "\nTotal Executed: " << total_tests << std::endl;
        std::cout << "Total Passed: " << total_passed << std::endl;
        std::cout << "Total Failed: " << total_failed << std::endl;
    }

    void TestRunner::add_test_set(const std::string& name, std::function<void(TestRunner * runner, cpp::test_set_results& results)> testSet)
    {
        test_fixtures.insert( std::pair<std::string, std::function<void(TestRunner * runner, cpp::test_set_results& results)>>(name, testSet) );
    }

    void TestRunner::run_tests()
    {
        test_results.clear();
        for(auto ts : test_fixtures)
        {
            cpp::test_set_results results;

            ts.second(this, results);
            std::cout << "\nTest Summary: " << results.tests_passed << " passed, " << results.tests_failed << " failed.\n";

            test_results.insert( std::pair<std::string, cpp::test_set_results>(ts.first, results) );
        }
    }

    void TestRunner::execute_test(cpp::test_set_results& results, const std::string& name, bool (*test)(void))
    {
        auto success = false;
        try {
            success = (*test)();
        } catch (...) {
            
        }

        report_test(name, success);
        success ? results.tests_passed++ : results.tests_failed++;
        results.test_set_count++;
    }

    void TestRunner::report_test(const std::string& name, bool result) {
        if (result) {
            std::cout << "✅ [PASS] " << name << "\n";
        } else {
            std::cout << "❌ [FAIL] " << name << "\n";
        }
    }

}