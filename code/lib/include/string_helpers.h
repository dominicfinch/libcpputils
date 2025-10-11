
#pragma once

#include "macros.h"

#include <sstream>
#include <algorithm>
#include <cctype>
#include <vector>
#include <memory>
#include <cstdio>
#include <cstdarg>

namespace iar {
    namespace utils {

        std::string toLower(std::string& s);
        std::string toUpper(std::string& s);

        bool endsWith(std::string& qstr, const char * substr, bool case_sensitive = true);
        bool endsWith(std::string& qstr, std::string& substr, bool case_sensitive = true);

        bool startsWith(std::string& qstr, const char * substr, bool case_sensitive = true);
        bool startsWith(std::string& qstr, std::string& substr, bool case_sensitive = true);

        template <class T>
        std::string replace(std::string qstr, const char * find, T replace);

        template <>
        std::string replace(std::string qstr, const char * find, int replace);

        template <>
        std::string replace(const std::string qstr, const char * find, float replace);

        template <>
        std::string replace(std::string qstr, const char * find, double replace);

        template <>
        std::string replace(const std::string qstr, const char * find, bool replace);

        template <>
        std::string replace(const std::string qstr, const char * find, std::string replace);

        template <>
        std::string replace(std::string qstr, const char * find, const char * replace);

        template <class T>
        std::string listConcat(std::vector<T>& data, const std::string join_str = ",", const std::string prefix_str = "(", const std::string suffix_str = ")") {
            std::stringstream ss;
            ss << prefix_str;
            for(auto i=0; i<data.size(); i++) {
                ss << data[i];
                if(i != data.size() - 1)
                    ss << join_str;
            }
            ss << suffix_str;
            return ss.str();
        }

        std::vector<std::string> split(const std::string qstr, const char * delim = ",", bool filter_empties = true);

        template <class ... Args>
        std::string stringFormat(const std::string& format, Args ... args ) {
            size_t size = snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
            std::unique_ptr<char[]> buf( new char[ size ] );
            snprintf( buf.get(), size, format.c_str(), args ... );
            return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
        }
        
        template <class ... Args>
        std::string stringFormat(const std::string& format, const char * arg1, Args ... args) {
            size_t size = snprintf( nullptr, 0, format.c_str(), arg1, args ... ) + 1; // Extra space for '\0'
            std::unique_ptr<char[]> buf( new char[ size ] );
            snprintf( buf.get(), size, format.c_str(), arg1, args ... );
            return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
        }

        /* Just redirect to alternative implementation */
        template <class ... Args>
        std::string stringFormat(const std::string& format, const std::string& arg1, Args ... args) {
            size_t size = snprintf( nullptr, 0, format.c_str(), arg1.c_str(), args ... ) + 1; // Extra space for '\0'
            std::unique_ptr<char[]> buf( new char[ size ] );
            snprintf( buf.get(), size, format.c_str(), arg1.c_str(), args ... );
            return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
        }
    }
}