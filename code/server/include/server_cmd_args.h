#ifndef _SEC_CHAT_SERVER_CMD_ARGS_H_
#define _SEC_CHAT_SERVER_CMD_ARGS_H_

#include "argtable3/argtable3.h"
#include <vector>
#include <string>
#include <json/json.h>

namespace iar {

namespace app {



    class SecChatServerCmdArgParser {
    public:
        SecChatServerCmdArgParser();
        ~SecChatServerCmdArgParser();

        int parse(int argc, char* argv[]);

        Json::Value config() { return _parsedConfig; }

    protected:
        bool load_config(const std::string& path);

    private:
        struct arg_lit* _help;
        struct arg_lit* _version;
        struct arg_file* _config;
        struct arg_end* _end;
        void* _argtable[4];

        Json::Value _parsedConfig;
    };

}
}

#endif
