#pragma once

#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QAction>
#include <QtWidgets/QMenu>
/*
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMenu>
*/

#include "help_dialog.h"


namespace iar { namespace ui {


    class SecChatClientGUI : public QMainWindow
    {
        Q_OBJECT

        public:
            SecChatClientGUI(QApplication& app, QWidget *parent = nullptr);
            virtual ~SecChatClientGUI();

            void createMenus();
            void createActions();
        
        private slots:
            void quitAction();

        private:
            QApplication * application = nullptr;
            QMenu * fileMenu = nullptr;
            QMenu * helpMenu = nullptr;

            HelpDialog * helpDialog = nullptr;

            QAction *exitAct = nullptr;
            QAction *helpAct = nullptr;

    };

}}
