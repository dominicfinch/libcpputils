#ifndef _SEC_CHAT_CLIENT_CMD_ARGS_H_
#define _SEC_CHAT_CLIENT_CMD_ARGS_H_

#include "argtable3/argtable3.h"
#include <vector>
#include <string>
#include <json/json.h>

namespace iar {

namespace app {



    class SecChatClientCmdArgParser {
    public:
        SecChatClientCmdArgParser();
        ~SecChatClientCmdArgParser();

        int parse(int argc, char* argv[]);

        Json::Value config() { return _parsedConfig; }
        const std::string& rpc_method() { return _rpcMethod; }
        const std::string& input_json_filepath() { return _inputJsonFilepath; }
        const bool interactive_mode() { return _interactiveMode; }

    protected:
        bool load_config(const std::string& path);

    private:
        struct arg_lit* _help;
        struct arg_lit* _version;
        struct arg_lit* _interactive_flag;

        struct arg_file* _config;
        struct arg_str* _rpc_method;
        struct arg_file* _input_json;
        
        struct arg_end* _end;
        void* _argtable[7];

        Json::Value _parsedConfig;
        std::string _rpcMethod;
        std::string _inputJsonFilepath;
        bool _interactiveMode = false;
    };

}
}

#endif
