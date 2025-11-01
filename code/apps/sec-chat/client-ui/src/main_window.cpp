
#include "main_window.h"
#include <QtWidgets/QMenuBar>
#include <QtCore/QTranslator>
#include <QtGui/QIcon>
#include <QtWidgets/QMessageBox>
#include <QtGui/QCloseEvent>

iar::ui::SecChatClientGUI::SecChatClientGUI(QApplication& app, QWidget *parent) : QMainWindow(parent), application(&app)
{
    //setupUi(this);
    createActions();
    createMenus();
}

iar::ui::SecChatClientGUI::~SecChatClientGUI()
{

    if(fileMenu != nullptr)
    {
        delete fileMenu;
    }

    if(exitAct != nullptr)
    {
        delete exitAct;
    }

    if(helpMenu != nullptr)
    {
        delete helpMenu;
    }

    if(helpAct != nullptr)
    {
        delete helpAct;
    }
}


void iar::ui::SecChatClientGUI::createMenus()
{
    fileMenu = menuBar()->addMenu(tr("&File"));
    //fileMenu->addAction();
    //fileMenu->addAction(openAct);
    //fileMenu->addAction(saveAct);
    //fileMenu->addAction(printAct);
    fileMenu->addSeparator();
    fileMenu->addAction(exitAct);

    helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(helpAct);

    menuBar()->show();
}

void iar::ui::SecChatClientGUI::createActions()
{
    exitAct = new QAction(tr("&Quit"), this);
    exitAct->setShortcuts(QKeySequence::Quit);
    exitAct->setStatusTip(tr("quit application"));
    connect(exitAct, &QAction::triggered, this, &SecChatClientGUI::quitAction);

    helpAct = new QAction(tr("&Help"), this);
    helpAct->setShortcuts(QKeySequence::HelpContents);
    helpAct->setStatusTip(tr("application help"));

    // Connect Help -> About
    connect(helpAct, &QAction::triggered, this, [this]() {
        HelpDialog helpDialog(this);
        helpDialog.exec();  // show modally
    });

}

void iar::ui::SecChatClientGUI::quitAction()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(
        this,
        "Confirm Exit",
        "Are you sure you want to quit?",
        QMessageBox::Yes | QMessageBox::No
    );

    if(reply == QMessageBox::Yes)
    {
        application->quit();
    }

}