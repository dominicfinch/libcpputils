#pragma once

#include <QtWidgets/QDialog>

class QLabel;
class QVBoxLayout;
class QHBoxLayout;
class QPushButton;
class QGraphicsWebView;  // For embedded map


namespace iar { namespace ui {

    class HelpDialog : public QDialog
    {
        Q_OBJECT

        public:

            HelpDialog(QWidget * parent = nullptr);


        private:
            int size[2] = {800, 600};
            
            QLabel *logoLabel;
            QLabel *infoLabel;
            //QGraphicsWebView *mapView;
    };

}}