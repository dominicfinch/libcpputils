#pragma once

#include <QtWidgets/QDialog>

class QLabel;
class QVBoxLayout;
class QHBoxLayout;
class QPushButton;


namespace iar { namespace ui {

    class ProfileCRUDDialog : public QDialog
    {
        Q_OBJECT

        public:

            ProfileCRUDDialog(QWidget * parent = nullptr);


        private:
            int size[2] = {800, 600};
            
            QLabel *logoLabel;
            QLabel *infoLabel;
            //QGraphicsWebView *mapView;
    };

}}