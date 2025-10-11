
#pragma once

#include <functional>

namespace iar {
    namespace utils {

        template <class ListObject>
        class LinkedList {
        public:
            LinkedList() : head(nullptr), tail(nullptr), size_(0) {}
            ~LinkedList() { clear(); }

            // Add to end
            void append(const ListObject& value) {
                Node* node = new Node(value);
                if (!head) {
                    head = tail = node;
                } else {
                    tail->next = node;
                    tail = node;
                }
                size_++;
            }

            // Add to beginning
            void prepend(const ListObject& value) {
                Node* node = new Node(value);
                node->next = head;
                head = node;
                if (!tail) tail = head;
                size_++;
            }

            // Remove first occurrence
            bool remove(const ListObject& value) {
                Node* current = head;
                Node* previous = nullptr;

                while (current) {
                    if (current->data == value) {
                        if (previous) previous->next = current->next;
                        else head = current->next;
                        if (tail == current) tail = previous;
                        delete current;
                        size_--;
                        return true;
                    }
                    previous = current;
                    current = current->next;
                }
                return false;
            }

            // Traverse with callback
            void for_each(const std::function<void(const ListObject&)>& callback) const {
                Node* current = head;
                while (current) {
                    callback(current->data);
                    current = current->next;
                }
            }

            // Get number of elements
            size_t size() const { return size_; }

            // Clear list
            void clear() {
                Node* current = head;
                while (current) {
                    Node* tmp = current;
                    current = current->next;
                    delete tmp;
                }
                head = tail = nullptr;
                size_ = 0;
            }

        private:
            struct Node {
                ListObject data;
                Node* next;
                Node(const ListObject& d) : data(d), next(nullptr) {}
            };

            Node* head;
            Node* tail;
            size_t size_;
        };

    }
}