
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
    std::stringstream ss;
    auto llvl = spdlog::level::info;

    switch (signum)
    {
        case SIGABRT:
        case SIGSEGV:
        case SIGTERM:
            ss << "Fatal error occurred. Application terminating.";
            llvl = spdlog::level::critical;
            break;
        case SIGINT:
            ss << "Interrupt signal (" << signum << ") received.";
            break;
    }

    securityService->LogMessage(ss.str(), llvl);
    if(securityService != nullptr && securityService->Server() != nullptr)
    {
        securityService->Server()->Shutdown();
    }
}

int main(int argc, char * argv[])
{
    signal(SIGINT, signalHandler);
    signal(SIGABRT, signalHandler);
    signal(SIGSEGV, signalHandler);
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