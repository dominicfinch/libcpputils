
/*
 © Copyright 2025 Dominic Finch
*/

#include <iostream>
#include <csignal>
#include "server_cmd_args.h"
#include "server.h"

iar::app::SecurityService * securityService = nullptr;

void signalHandler(int signum)
{
    std::cout << " - Interrupt signal (" << signum << ") received.\n";
    if(securityService != nullptr && securityService->Server() != nullptr)
    {
        securityService->Server()->Shutdown();
    }
}

int main(int argc, char * argv[])
{
    signal(SIGINT, signalHandler);
    signal(SIGABRT, signalHandler);
    signal(SIGTERM, signalHandler);

    iar::app::SecurityServiceCmdArgParser cmdArgParser;
    if(cmdArgParser.parse(argc, argv) == 0)
    {
        securityService = new iar::app::SecurityService;
        auto config = cmdArgParser.config();
        if(securityService->Initialize(config))
        {
            securityService->Run();
        }
        delete securityService;
    }
    return 0;
}