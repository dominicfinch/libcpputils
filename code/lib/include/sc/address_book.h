#pragma once

#include <map>
#include <string>
#include <vector>

#include "sc/contact.h"

namespace iar { namespace utils {

    class SCAddressBook
    {
        public:
            
            void setRootDir(const std::string& dir) { rootDir = dir; }

            std::map<std::string, SCContact>& Book() { return _book; }


        private:
            std::map<std::string, SCContact> _book;
            std::string baseDir = "address-book/";
            std::string rootDir;
    };

}}