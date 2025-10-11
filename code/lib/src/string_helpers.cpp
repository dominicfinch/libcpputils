
#include "string_helpers.h"

namespace iar {
    namespace utils {

        std::string toLower(std::string& s) {
            std::transform(s.begin(), s.end(), s.begin(),
                [](unsigned char c){ return std::tolower(c); }
            );
            return s;
        }

        std::string toUpper(std::string& s) {
            std::transform(s.begin(), s.end(), s.begin(),
                [](unsigned char c){ return std::toupper(c); }
            );
            return s;
        }

        bool endsWith(std::string& qstr, const char * substr, bool case_sensitive) {
            std::string subs(substr);
            return endsWith(qstr, subs, case_sensitive);
        }

        bool endsWith(std::string& qstr, std::string& substr, bool case_sensitive) {
            if(qstr.length() >= substr.length()) {
                if(!case_sensitive) {
                    qstr = toLower(qstr);
                    substr = toLower(substr);
                }
                return qstr.compare(qstr.length() - substr.length(), substr.length(), substr) == 0 ? true : false;
            }
            else
                return false;
        }

        bool startsWith(std::string& qstr, const char * substr, bool case_sensitive) {
            std::string subs(substr);
            return startsWith(qstr, subs, case_sensitive);
        }

        bool startsWith(std::string& qstr, std::string& substr, bool case_sensitive) {
            if(qstr.length() >= substr.length()) {
                if(!case_sensitive) {
                    qstr = toLower(qstr);
                    substr = toLower(substr);
                }
                return qstr.compare(0, substr.length(), substr) == 0 ? true : false;
            }
            else
                return false;
        }

        // TODO: REFACTOR UTILS - GET RID OF DUPLICATION //
        template <class T>
        std::string replace(const std::string qstr, const char * find, T replace) {
            return utils::replace<T>(qstr, find, replace);
        }

        template <>
        std::string replace(const std::string qstr, const char * find, int replace) {
            size_t start = qstr.find(find);
            size_t end = start + strlen(find);
            std::stringstream ss;
            ss << qstr.substr(0, start) << replace << qstr.substr(end, qstr.length());
            return ss.str();
        }

        template <>
        std::string replace(const std::string qstr, const char * find, float replace) {
            return utils::replace(qstr, find, static_cast<double>(replace));
        }

        template <>
        std::string replace(const std::string qstr, const char * find, double replace) {
            size_t start = qstr.find(find);
            size_t end = start + strlen(find);
            std::stringstream ss;
            ss << qstr.substr(0, start) << replace << qstr.substr(end, qstr.length());
            return ss.str();
        }

        template <>
        std::string replace(const std::string qstr, const char * find, bool replace) {
            size_t start = qstr.find(find);
            size_t end = start + strlen(find);
            std::stringstream ss;
            ss << qstr.substr(0, start) << (replace ? "true" : "false") << qstr.substr(end, qstr.length());
            return ss.str();
        }

        template <>
        std::string replace(const std::string qstr, const char * find, const char * replace) {
            size_t start = qstr.find(find);
            size_t end = start + strlen(find);
            std::stringstream ss;
            ss << qstr.substr(0, start) << replace << qstr.substr(end, qstr.length());
            return ss.str();
        }

        template <>
        std::string replace(const std::string qstr, const char * find, std::string replace) {
            return utils::replace(qstr, find, replace.c_str());
        }

        std::vector<std::string> split(const std::string qstr, const char * delim, bool filter_empties) {
            std::vector<std::string> splits;
            std::string pstr = qstr;
            size_t p0 = -1;
            do {
                pstr = pstr.substr(p0 + 1, pstr.length() - p0);
                p0 = pstr.find(delim);
                if(filter_empties) {
                    std::string extracted = pstr.substr(0, p0);
                    if(!extracted.empty())
                        splits.push_back(extracted);
                } else
                    splits.push_back(pstr.substr(0, p0));
            } while(p0 != std::string::npos);
            return splits;
        }
    }
}