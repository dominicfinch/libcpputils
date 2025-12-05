/*
 © Copyright 2025 Dominic Finch
*/

#include <iostream>
#include "main_window.h"

#define DEFAULT_WINDOW_SIZE_X       800
#define DEFAULT_WINDOW_SIZE_Y       600

int main(int argc, char * argv[])
{
    QApplication app(argc, argv);

    // Instantiate an object of our application class
    iar::ui::FDiskGUI secChatClientApp(app);
    secChatClientApp.setWindowTitle("File & Disk Security Tool");
    secChatClientApp.setFixedSize(DEFAULT_WINDOW_SIZE_X, DEFAULT_WINDOW_SIZE_Y);

    secChatClientApp.show();

    // Run the application event loop
    return app.exec();
}
