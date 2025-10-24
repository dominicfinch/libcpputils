#include "client_cmd_args.h"
#include "constants.h"
#include "file.h"
#include <iostream>

iar::app::SecChatClientCmdArgParser::SecChatClientCmdArgParser() {
    _help   = arg_lit0("h", "help", "Display this help and exit");
    _version = arg_lit0("v", "version", "Display version information");
    _interactive_flag = arg_lit0("i", "interactive", "Permit entry of RPC input data via console");

    _config  = arg_file1("c", "config", "<file>", "Path to JSON configuration file");
    _rpc_method = arg_str1("m", "method", "<method>", "Specifies the RPC endpoint to request");
    _input_json = arg_file0("f", "input-file", "<file>", "Path to JSON file to be used in RPC request");
    _end     = arg_end(10);

    _argtable[0] = _help;
    _argtable[1] = _version;
    _argtable[2] = _interactive_flag;

    _argtable[3] = _config;
    _argtable[4] = _rpc_method;
    _argtable[5] = _input_json;
    _argtable[6] = _end;
}

iar::app::SecChatClientCmdArgParser::~SecChatClientCmdArgParser() {
    arg_freetable(_argtable, sizeof(_argtable) / sizeof(_argtable[0]));
}

int iar::app::SecChatClientCmdArgParser::parse(int argc, char* argv[]) {
    int nerrors = arg_parse(argc, argv, _argtable);

    if (_help->count > 0) {
        std::cout << "Usage: " << argv[0] << " [options]\n";
        arg_print_glossary(stdout, _argtable, "  %-25s %s\n");
        return -1;
    }

    if (_version->count > 0) {
        std::cout << APP_PRETTY_NAME << "  " << APP_VERSION_STR << "\n";
        std::cout << "  branch: " << GIT_BRANCH << "\n";
        std::cout << "  commit: " << GIT_COMMIT << "\n";
        return -1;
    }

    if (nerrors > 0) {
        arg_print_errors(stderr, _end, argv[0]);
        std::cerr << "Try '" << argv[0] << " --help' for more information.\n";
    } else {
        // Check -i or -f are specified (at least one must be specified)
        if( (_interactive_flag->count > 0) && (_input_json->count == 0) ) {
            // Interactive mode selected
            _interactiveMode = true;
        } else if( (_interactive_flag->count == 0) && (_input_json->count > 0) ) {
            // File input mode selected
            _inputJsonFilepath = _input_json->filename[0];

            if(!iar::utils::file_exists(_inputJsonFilepath)) {
                std::cerr << "Error when parsing command line arguments:\n";
                std::cerr << " - Unable to find input file: " << _inputJsonFilepath << "\n";
                nerrors++;
            }
        } else if( (_interactive_flag->count == 0) && (_input_json->count == 0) ) {
            // Default to interactive mode if no input file specified
            _interactiveMode = true;
        } else {
            // Selection is invalid
            std::cerr << "Error when parsing command line arguments:\n";
            std::cerr << " - Interactive mode (-i / --interactive) and file input mode (-f / --input-file) are mutually exclusive\n";
            nerrors++;
        }

        // Store method
        _rpcMethod = _rpc_method->sval[0];

        if (_config->count > 0) {
            std::string filepath = _config->filename[0];
            if (!load_config(filepath)) nerrors++;
        } else {
            std::cout << " - No config file provided.\n";
            nerrors++;
        }
    }
    return nerrors;
}

bool iar::app::SecChatClientCmdArgParser::load_config(const std::string& path)
{
    if(!iar::utils::read_json_file(path, _parsedConfig))
    {
        std::cerr << " - Failed to read JSON file: " << path << "\n";
        return false;
    }
    return true;
}