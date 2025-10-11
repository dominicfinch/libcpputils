
#ifndef IAR_UTILS_FILE_HPP
#define IAR_UTILS_FILE_HPP

#include <fstream>
#include <istream>
#include <string>
#include <sstream>

#include <experimental/filesystem>

namespace iar { namespace utils {

    bool file_exists(const std::string& fpath);

    bool directory_exists(const std::string& fpath);

    bool create_directories(const std::string& fpath);

    bool read_file_contents(const std::string& fpath, std::string& contents, std::ios_base::openmode mode = std::ios_base::in );

    bool write_file_contents(const std::string& fpath, const std::string& contents, std::ios_base::openmode mode = std::ios_base::out | std::ios_base::trunc );

}}

#endif
