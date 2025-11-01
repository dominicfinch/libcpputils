
#include <iostream>
#include <sstream>
#include <csignal>

#include "ecc.h"
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

    iar::utils::ECC ecc;
    ecc.generate_own_keypair();
    ecc.export_public_key("ecc.public.pem");
    ecc.export_private_key("ecc.private.pem");
    
    std::string contactFilepath = "client.contact.json";    // TODO: Make this customizable
    if(cmdArgParser.parse(argc, argv) == 0)
    {
        if(chatClient.Initialize(cmdArgParser.config()))
        {
            // Prepare client keys
            if(iar::utils::file_exists(contactFilepath)) {
                Json::Value value;
                if(iar::utils::read_json_file(contactFilepath, value)) {
                    chatClient.Self().fromJSON(value);
                } else {
                    // Failed to read from contact filepath although file exists (i.e. issue with JSON)
                }
            } else {
                chatClient.Self().autoGenerateKeys();
                auto contactInfo = chatClient.Self().toJSON(true);
                iar::utils::write_json_file(contactFilepath, contactInfo);
            }

            Json::Value params = chatClient.Self().toJSON();

            std::cout << params;

            // Negotiate handshake with server


            // Prepare input data


            // Make request


            // Record response

            if(cmdArgParser.interactive_mode()) {
                // Get JSON input from user
            } else {
                //if(iar::utils::read_json_file(cmdArgParser.input_json_filepath(), params)) {

                //}
            }

            try {
                Json::Value result = chatClient.CallMethod(cmdArgParser.rpc_method(), params);
                std::cout << "Result: " << result << std::endl;
            } catch (const jsonrpc::JsonRpcException &e) {
                std::cerr << "RPC error: " << e.what() << std::endl;
            }
        } else {
            std::cout << " - Errors detected in configuration file. Failed to initialize client\n";
        }
    }
    return 0;
}