#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_PSIPMLSW.h"
#include "myQthread.h"
#include <tins/tins.h>
#include <string>
#include <mutex>
#include <vector>
#include <QHash>

static std::map<std::string, std::map<int, int> > cam_table;
static QHash<uint, int> hash_port1;
static QHash<uint, int> hash_port2;
static int counterEthernetII_port1 = 0;
static int counterEthernetII_port2 = 0;
static int counterARP_port1 = 0;
static int counterARP_port2 = 0;
static int counterIP_port1 = 0;
static int counterIP_port2 = 0;
static int counterICMP_port1 = 0;
static int counterICMP_port2 = 0;
static int counterHTTP_port1 = 0;
static int counterHTTP_port2 = 0;
static int counterTCP_port1 = 0;
static int counterTCP_port2 = 0;
static int counterUDP_port1 = 0;
static int counterUDP_port2 = 0;
static int aging = 30;
static std::mutex mutex;


class PSIPMLSW : public QMainWindow
{
    Q_OBJECT

public:
    PSIPMLSW(QWidget *parent = Q_NULLPTR);
    Ui::PSIPMLSWClass ui;
    MyQthread::QThread myQthread;
    bool callback_port1(Tins::PDU&);
    bool callback_port2(Tins::PDU&);
    void port1();
    void port2();
    void timer();
    
    bool wait_for_thread = false;
    std::mutex threadMutex;
private:
    
    
public slots:
    void start();
    void clear();
    void buffer();
    void print_table();
    void set_aging();
};

