
#pragma once

#include <functional>
#include <memory>

namespace iar { namespace utils {

    template <typename T, typename Compare = std::less<T>>
    class BinaryTree {
    private:
        struct Node {
            T data;
            std::unique_ptr<Node> left;
            std::unique_ptr<Node> right;

            explicit Node(const T& value) : data(value), left(nullptr), right(nullptr) {}
        };

        std::unique_ptr<Node> root;
        Compare comp;
        size_t count = 0;

        bool insert(std::unique_ptr<Node>& node, const T& value) {
            if (!node) {
                node = std::make_unique<Node>(value);
                return true;
            } else if (value == node->data) {
                return false;
            } else if (comp(value, node->data)) {
                return insert(node->left, value);
            } else {
                return insert(node->right, value);
            }
            return false;
        }

        bool contains(const std::unique_ptr<Node>& node, const T& value) const {
            if (!node) return false;
            if (value == node->data) return true;
            return comp(value, node->data)
                ? contains(node->left, value)
                : contains(node->right, value);
        }

        const T* search(const std::unique_ptr<Node>& node, const T& value) const {
            if (!node) return nullptr;
            if (value == node->data) return &node->data;
            return comp(value, node->data)
                ? search(node->left, value)
                : search(node->right, value);
        }

        T* search(std::unique_ptr<Node>& node, const T& value) {
            if (!node) return nullptr;
            if (value == node->data) return &node->data;
            return comp(value, node->data)
                ? search(node->left, value)
                : search(node->right, value);
        }

        // In-order traversal
        void in_order(const std::unique_ptr<Node>& node, const std::function<void(const T&)>& fn) const {
            if (!node) return;
            in_order(node->left, fn);
            fn(node->data);
            in_order(node->right, fn);
        }

        // Clear the tree
        void clear(std::unique_ptr<Node>& node) {
            node.reset();
        }

        // Internal remove helper
        bool remove(std::unique_ptr<Node>& node, const T& value) {
            if (!node) return false;

            if (value < node->data) {
                return remove(node->left, value);
            } else if (value > node->data) {
                return remove(node->right, value);
            } else {
                // Found the node
                if (!node->left) {
                    node = std::move(node->right);
                } else if (!node->right) {
                    node = std::move(node->left);
                } else {
                    // Two children: replace with in-order successor
                    Node* minNode = find_min(node->right.get());
                    node->data = minNode->data;
                    remove(node->right, minNode->data);
                }
                return true;
            }
        }

        // Find min node in a subtree
        Node* find_min(Node* node) {
            while (node->left)
                node = node->left.get();
            return node;
        }

    public:
        BinaryTree(Compare cmp = Compare()) : comp(cmp) {}
        ~BinaryTree() = default;

        bool insert(const T& value) {
            if (insert(root, value)) {
                ++count;
                return true;
            }
            return false;
        }

        bool contains(const T& value) const {
            return contains(root, value);
        }

        const T* search(const T& value) const {
            return search(root, value);
        }

        T* search(const T& value) {
            return search(root, value);
        }

        void in_order(const std::function<void(const T&)>& fn) const {
            in_order(root, fn);
        }

        void clear() {
            clear(root);
            count = 0;
        }

        size_t size() const {
            return count;
        }

        bool empty() const {
            return count == 0;
        }

        bool remove(const T& value) {
            size_t before = count;
            if (remove(root, value)) {
                --count;
                return true;
            }
            return false;
        }
    };

}}