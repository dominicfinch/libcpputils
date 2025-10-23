#include "client_cmd_args.h"
#include "constants.h"
#include "file.h"
#include <iostream>

iar::app::SecChatClientCmdArgParser::SecChatClientCmdArgParser() {
    _help   = arg_lit0("h", "help", "Display this help and exit");
    _version = arg_lit0("v", "version", "Display version information");
    _config  = arg_file0("c", "config", "<file>", "Path to JSON configuration file");
    _end     = arg_end(10);

    _argtable[0] = _help;
    _argtable[1] = _version;
    _argtable[2] = _config;
    _argtable[3] = _end;
}

iar::app::SecChatClientCmdArgParser::~SecChatClientCmdArgParser() {
    arg_freetable(_argtable, sizeof(_argtable) / sizeof(_argtable[0]));
}

int iar::app::SecChatClientCmdArgParser::parse(int argc, char* argv[]) {
    int nerrors = arg_parse(argc, argv, _argtable);

    if (_help->count > 0) {
        std::cout << "Usage: " << argv[0] << " [options]\n";
        arg_print_glossary(stdout, _argtable, "  %-25s %s\n");
        return 0;
    }

    if (_version->count > 0) {
        std::cout << APP_PRETTY_NAME << "  " << APP_VERSION_STR << "\n";
        std::cout << "  branch: " << GIT_BRANCH << "\n";
        std::cout << "  commit: " << GIT_COMMIT << "\n";
        return 0;
    }

    if (nerrors > 0) {
        arg_print_errors(stderr, _end, argv[0]);
        std::cerr << "Try '" << argv[0] << " --help' for more information.\n";
        return nerrors;
    }

    if (_config->count > 0) {
        std::string filepath = _config->filename[0];
        if (!load_config(filepath)) { return 1; }
    } else {
        std::cout << "No config file provided.\n";
    }
    return 0;
}

bool iar::app::SecChatClientCmdArgParser::load_config(const std::string& path)
{
    return iar::utils::read_json_file(path, _parsedConfig);
}