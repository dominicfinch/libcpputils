
#include "llist_tests.h"
#include "llist.h"
#include <string>

bool test_append_and_size() {
    iar::utils::LinkedList<int> list;
    list.append(1);
    list.append(2);
    list.append(3);
    return list.size() == 3;
}

bool test_prepend_and_order() {
    iar::utils::LinkedList<std::string> list;
    list.prepend("C");
    list.prepend("B");
    list.prepend("A");

    std::string result;
    list.for_each([&](const std::string& val) {
        result += val;
    });

    return result == "ABC";
}

bool test_remove_existing_element() {
    iar::utils::LinkedList<int> list;
    list.append(1);
    list.append(2);
    list.append(3);

    bool removed = list.remove(2);
    int sum = 0;
    list.for_each([&](int val) {
        sum += val;
    });

    return removed && sum == (1 + 3) && list.size() == 2;
}

bool test_remove_nonexistent_element() {
    iar::utils::LinkedList<int> list;
    list.append(1);
    list.append(2);

    bool removed = list.remove(99);
    return !removed && list.size() == 2;
}

bool test_clear_list() {
    iar::utils::LinkedList<int> list;
    list.append(5);
    list.append(10);
    list.clear();
    return list.size() == 0;
}

bool test_for_each_accumulates_values() {
    iar::utils::LinkedList<int> list;
    list.append(1);
    list.append(2);
    list.append(3);

    int total = 0;
    list.for_each([&](int val) {
        total += val;
    });

    return total == 6;
}

bool test_append_after_clear() {
    iar::utils::LinkedList<std::string> list;
    list.append("first");
    list.clear();
    list.append("second");

    std::string result;
    list.for_each([&](const std::string& val) {
        result += val;
    });

    return result == "second" && list.size() == 1;
}
