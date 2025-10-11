
#include "file.h"

namespace ex = std::experimental;
namespace fs = std::experimental::filesystem;

namespace iar { namespace utils {

    bool file_exists(const std::string& fpath) {
        return fs::exists( fs::path( fpath.c_str() ) ) && fs::is_regular_file( fs::path(fpath.c_str()) );
    }

    bool directory_exists(const std::string& fpath) {
        return fs::exists( fs::path( fpath.c_str() ) ) && fs::is_directory( fs::path(fpath.c_str()) );
    }

    bool create_directories(const std::string& fpath) {
        return fs::create_directories(fpath.c_str());
    }

    bool read_file_contents(const std::string& fpath, std::string& contents, std::ios_base::openmode mode) {
        //std::fstream fs;
        std::ifstream istream;
        std::stringstream ss;

        istream.open(fpath, mode);

        if(!istream.good())
            return false;

        ss << istream.rdbuf();
        istream.close();

        contents = ss.str();
        return true;
    }

    bool write_file_contents(const std::string& fpath, const std::string& contents, std::ios_base::openmode mode ) {
        std::ofstream ostream;
        ostream.open(fpath, mode);

        if(!ostream.good())
            return false;

        ostream << contents;

        ostream.close();
        return true;
    }

}}
