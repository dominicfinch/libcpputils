
#include "help_dialog.h"


#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtGui/QPixmap>

#include <QtWebKitWidgets/QGraphicsWebView>
#include <QtGui/QDesktopServices>
#include <QtCore/QUrl>

iar::ui::HelpDialog::HelpDialog(QWidget * parent): QDialog(parent)
{
    setWindowTitle("About / Help");
    setBaseSize(600, 300);
    setMinimumSize(600, 300);

    // --- Company Logo ---
    logoLabel = new QLabel(this);
    QPixmap logo("logo.svg");  // put your logo in Qt resources
    logoLabel->setPixmap(logo.scaled(120, 120, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    logoLabel->setAlignment(Qt::AlignCenter);

    // --- Company Info with Hyperlink ---
    infoLabel = new QLabel(this);
    infoLabel->setTextFormat(Qt::RichText);
    infoLabel->setOpenExternalLinks(true);
    infoLabel->setText(
        "<p>Providing innovative software solutions since 19XX.</p>"
        "<p>Visit us at: "
        "<a href='https://www.iar.com'>www.iar.com</a></p>"
        "<p>Contact: support@iar.com</p>"
    );
    infoLabel->setAlignment(Qt::AlignCenter);

    // --- Embedded Map (Google Maps or OSM) ---
    //mapView = new QGraphicsWebView();
    //mapView->setMinimumHeight(300);
    //mapView->setUrl(QUrl("https://www.google.com/maps/place/1600+Amphitheatre+Parkway,+Mountain+View,+CA"));

    // --- Layout ---
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(logoLabel);
    mainLayout->addWidget(infoLabel);
    //mainLayout->addWidget((QWidget*)mapView);

    setLayout(mainLayout);
}