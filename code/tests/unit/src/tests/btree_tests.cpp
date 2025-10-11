
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <iostream>

#include "btree_tests.h"
#include "btree.h"

bool test_insert_and_contains() {
    iar::utils::BinaryTree<int> tree;
    return tree.insert(10) && tree.insert(5) && tree.insert(15)
           && tree.contains(10)
           && tree.contains(5)
           && tree.contains(15)
           && !tree.contains(99);
}

bool test_insert_duplicates() {
    iar::utils::BinaryTree<int> tree;
    return tree.insert(10)
           && !tree.insert(10)  // duplicate
           && tree.size() == 1;
}

bool test_in_order_traversal_sorted() {
    iar::utils::BinaryTree<int> tree;
    std::vector<int> values = {50, 30, 70, 20, 40, 60, 80};
    for (int v : values) tree.insert(v);

    std::vector<int> result;
    tree.in_order([&](const int& v) { result.push_back(v); });

    std::vector<int> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    return result == sorted;
}

bool test_remove_leaf_node() {
    iar::utils::BinaryTree<int> tree;
    tree.insert(10);
    tree.insert(5);
    tree.insert(15);
    return tree.remove(5) && !tree.contains(5) && tree.size() == 2;
}

bool test_remove_node_with_one_child() {
    iar::utils::BinaryTree<int> tree;
    tree.insert(10);
    tree.insert(5);
    tree.insert(2);  // 5 has one left child

    return tree.remove(5) && !tree.contains(5) && tree.contains(2) && tree.size() == 2;
}

bool test_remove_node_with_two_children() {
    iar::utils::BinaryTree<int> tree;
    tree.insert(10);
    tree.insert(5);
    tree.insert(15);
    tree.insert(12);
    tree.insert(18);

    return tree.remove(15)
           && !tree.contains(15)
           && tree.contains(12)
           && tree.contains(18)
           && tree.size() == 4;
}

bool test_remove_root_node() {
    iar::utils::BinaryTree<int> tree;
    tree.insert(10);
    tree.insert(5);
    tree.insert(15);

    return tree.remove(10)  // root
           && !tree.contains(10)
           && tree.size() == 2;
}

bool test_clear_tree() {
    iar::utils::BinaryTree<int> tree;
    tree.insert(1);
    tree.insert(2);
    tree.clear();
    return tree.empty() && tree.size() == 0 && !tree.contains(1);
}

bool test_empty_tree() {
    iar::utils::BinaryTree<int> tree;
    return tree.empty() && tree.size() == 0;
}

bool test_remove_nonexistent_node() {
    iar::utils::BinaryTree<int> tree;
    tree.insert(1);
    return !tree.remove(42) && tree.size() == 1;
}

bool test_string_payloads() {
    iar::utils::BinaryTree<std::string> tree;
    tree.insert("cat");
    tree.insert("dog");
    tree.insert("apple");

    std::vector<std::string> result;
    tree.in_order([&](const std::string& s) { result.push_back(s); });

    return result == std::vector<std::string>{"apple", "cat", "dog"};
}

bool test_search_found_and_not_found() {
    iar::utils::BinaryTree<int> tree;
    tree.insert(10);
    tree.insert(20);
    tree.insert(5);

    const int* found = tree.search(20);
    const int* not_found = tree.search(42);

    return found && *found == 20 && not_found == nullptr;
}

bool test_custom_comparator() {
    auto reverse_cmp = [](int a, int b) { return a > b; };

    iar::utils::BinaryTree<int, decltype(reverse_cmp)> tree(reverse_cmp);
    tree.insert(5);
    tree.insert(10);
    tree.insert(3);

    return tree.contains(10) && tree.contains(3) && !tree.contains(99);
}

bool test_mutable_search() {
    iar::utils::BinaryTree<std::string> tree;
    tree.insert("hello");
    tree.insert("world");

    std::string* val = tree.search("hello");
    if (!val) return false;

    *val = "HELLO";
    return tree.contains("HELLO") && !tree.contains("hello");
}