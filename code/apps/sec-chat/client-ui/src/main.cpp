#include <iostream>
#include "main_window.h"

#define DEFAULT_WINDOW_SIZE_X       1200
#define DEFAULT_WINDOW_SIZE_Y       800

int main(int argc, char * argv[])
{
    QApplication app(argc, argv);

    // Instantiate an object of our application class
    iar::ui::SecChatClientGUI secChatClientApp(app);
    secChatClientApp.setWindowTitle("Sec Chat Client UI");
    secChatClientApp.setFixedSize(DEFAULT_WINDOW_SIZE_X, DEFAULT_WINDOW_SIZE_Y);

    secChatClientApp.show();

    // Run the application event loop
    return app.exec();
}
