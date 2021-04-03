#ifndef MYQTHREAD_H
#define MYQTHREAD_H
#include <QtCore>

class MyQthread : public QThread {
    Q_OBJECT
public:
    explicit MyQthread(QObject* parent = 0);
    void run();
    
signals:

public slots:
};

#endif