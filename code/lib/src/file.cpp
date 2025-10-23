
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

    bool read_json_file(const std::string& fpath, Json::Value& contents, std::ios_base::openmode mode)
    {
        bool success = false;
        std::string fileContentStr;

        if(read_file_contents(fpath, fileContentStr, mode))
        {
            Json::CharReaderBuilder rbuilder;
            Json::CharReader * reader = rbuilder.newCharReader();
            std::string parseErrors;        // Note: this var is thrown away

            if(reader->parse(fileContentStr.data(), fileContentStr.data() + fileContentStr.size(),
                &contents, &parseErrors))
            {
                success = true;
            }
            delete reader;
        }
        return success;
    }

    bool write_json_file(const std::string& fpath, const Json::Value& contents, std::ios_base::openmode mode)
    {
        // Open output file stream with specified mode
        std::ofstream ofs(fpath, mode);
        if (!ofs.is_open()) {
            //std::cerr << "Error: Could not open file for writing: " << fpath << std::endl;
            return false;
        }

        try {
            // Configure writer for pretty output
            Json::StreamWriterBuilder writerBuilder;
            writerBuilder["indentation"] = "  "; // 2 spaces for readability
            std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());

            // Write JSON data to file
            writer->write(contents, &ofs);
            ofs.close();
        } catch (const std::exception& e) {
            //std::cerr << "Error while writing JSON to file: " << e.what() << std::endl;
            return false;
        }

        return true;
    }

}}
