
#include "runner.h"
#include <iostream>

namespace iar {

    void TestRunner::add_test_set(const std::string& name, std::function<void(TestRunner * runner, iar::test_set_results& results)> testSet)
    {
        test_fixtures.insert( std::pair<std::string, std::function<void(TestRunner * runner, iar::test_set_results& results)>>(name, testSet) );
    }

    void TestRunner::run_tests()
    {
        test_results.clear();
        for(auto ts : test_fixtures)
        {
            iar::test_set_results results;

            ts.second(this, results);
            std::cout << "\nTest Summary: " << results.tests_passed << " passed, " << results.tests_failed << " failed.\n";

            test_results.insert( std::pair<std::string, iar::test_set_results>(ts.first, results) );
        }
    }

    void TestRunner::execute_test(iar::test_set_results& results, const std::string& name, bool (*test)(void))
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