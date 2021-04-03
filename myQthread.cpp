#include "myQthread.h"
#include <QtCore>

MyQthread::MyQthread(QObject *parent):
	QThread(parent)
{
}

void MyQthread::run() {
	sleep(10);
}