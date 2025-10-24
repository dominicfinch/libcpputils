
#include <iostream>

#include "constants.h"
#include "server_cmd_args.h"
#include "server.h"

int main(int argc, char * argv[])
{
    iar::app::SecChatServerCmdArgParser cmdArgParser;

    if(cmdArgParser.parse(argc, argv) == 0)
    {
        auto port_number = cmdArgParser.config()["port"].asInt();
        port_number = port_number == 0 ? DEFAULT_SERVER_PORT : port_number;

        jsonrpc::HttpServer httpServer(port_number);
        iar::app::SecChatServer server(httpServer);

        if (server.StartListening()) {
            std::cout << "JSON-RPC server listening on port " << port_number << std::endl;
            std::cin.get(); // wait for user input
            server.StopListening();
        } else {
            std::cerr << "Error starting server" << std::endl;
        }
    }
    return 0;
}