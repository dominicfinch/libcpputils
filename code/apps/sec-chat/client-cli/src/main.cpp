
#include <iostream>
#include <sstream>
#include <csignal>


#include "client.h"
#include "client_cmd_args.h"
#include "file.h"
#include "base64.h"


void signal_handler(int signal)
{
    
}



int main(int argc, char * argv[])
{
    std::signal(SIGINT, signal_handler);
    std::signal(SIGABRT, signal_handler);
    std::signal(SIGTERM, signal_handler);


    iar::app::SecChatClientCmdArgParser cmdArgParser;
    iar::app::SecChatClient chatClient;
    if(cmdArgParser.parse(argc, argv) == 0)
    {
        if(chatClient.Initialize(cmdArgParser.config()))
        {

            chatClient.Self().autoGenerateKeys();
            //client->Self().exportContact();

            std::cout << "Name: " << chatClient.Self().Name() << "\n";

            std::string rsaPublicKey, eccPublicKey;
            chatClient.Self().rsaKey().public_key(rsaPublicKey);
            chatClient.Self().eccKey().get_own_public_key_pem(eccPublicKey);

            std::vector<uint8_t> rsaPKVect(rsaPublicKey.begin(), rsaPublicKey.end());
            std::vector<uint8_t> eccPKVect(eccPublicKey.begin(), eccPublicKey.end());

            std::cout << rsaPublicKey << std::endl;
            std::cout << eccPublicKey << std::endl;

            Json::Value params;
            params["rsa.pubkey"] = iar::utils::Base64::encode(rsaPKVect);
            params["ecc.pubkey"] = iar::utils::Base64::encode(eccPKVect);

            if(cmdArgParser.interactive_mode()) {
                // Get JSON input from user
            } else {
                if(iar::utils::read_json_file(cmdArgParser.input_json_filepath(), params)) {

                }
            }

            try {
                //Json::Value result = chatClient.CallMethod(cmdArgParser.rpc_method(), params);
                //std::cout << "Result: " << result << std::endl;
            } catch (const jsonrpc::JsonRpcException &e) {
                std::cerr << "RPC error: " << e.what() << std::endl;
            }
        } else {

        }
    }
    return 0;
}