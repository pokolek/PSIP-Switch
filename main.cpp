#include "PSIPMLSW.h"
#include "myQthread.h"
#include <QtWidgets/QApplication>
#include <tins/tins.h>
#include <thread>
#include <iostream>
#include <QtCore>

using namespace Tins;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    PSIPMLSW w;
    w.show();
    
    return a.exec();

    
}
