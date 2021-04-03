#include "PSIPMLSW.h"
#include "myQthread.h"
#include <tins/tins.h>
#include <thread>
#include <string>
#include <chrono>
#include <mutex>
#include <ctime>
#include <cstdlib>
#include <QDebug>
#include <QSpinBox>
#include <vector>
#include <QHash>




using namespace Tins;

PSIPMLSW::PSIPMLSW(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    QPushButton* startButton = PSIPMLSW::findChild<QPushButton*>("startButton"); //najdem tlacidlo
    connect(startButton, SIGNAL(released()), this, SLOT(start())); //spusti mi funkciu
    connect(&this->myQthread, SIGNAL(finished()), this, SLOT(print_table())); 


    QPushButton* setButton = PSIPMLSW::findChild<QPushButton*>("setButton"); //najdem tlacidlo
    connect(setButton, SIGNAL(released()), this, SLOT(set_aging())); //spusti mi funkciu

    QPushButton* clearButton = PSIPMLSW::findChild<QPushButton*>("clearButton"); //najdem tlacidlo
    connect(clearButton, SIGNAL(clicked()), this, SLOT(clear())); //spusti mi funkciu
}

void PSIPMLSW::set_aging() {
    QPushButton* button = (QPushButton*)sender();
    QSpinBox* spinBox = PSIPMLSW::findChild<QSpinBox*>("spinBox");
    aging = spinBox->value();
    qDebug() << spinBox->value();
}

void PSIPMLSW::timer() {
    clock_t startTime = clock(); //Start timer
    int secondsPassed;
    int secondsToDelay = 1;
    bool flag = true;
    //std::lock_guard<std::mutex> lock(this->threadMutex);
    while(1) {
        startTime = clock();
        flag = true;
        while (flag)
        {
            secondsPassed = (clock() - startTime) / CLOCKS_PER_SEC;
            if (secondsPassed >= secondsToDelay)
            {
                flag = false;
                break;
            }
        }
        this->myQthread.start();
        this->myQthread.quit();
        std::map<std::string, std::map<int, int> >::iterator itr;
        std::map<int, int>::iterator ptr;
        bool erased = false;
        for (itr = cam_table.begin(); itr != cam_table.end(); itr++) {
            for (ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
                ptr->second -= 1;
                if (ptr->second <= 0) {
                    cam_table.erase(itr);
                    erased = true;
                    break;
                }
            }
            if (erased)
                break;
        }   
    }
}

void PSIPMLSW::print_table() {
    this->ui.textEdit->setText(QString::fromStdString(
        "\tport1 IN:"
        "\n\t\tEthernetII: " + std::to_string(counterEthernetII_port2)
        + "\n\t\tARP:" + std::to_string(counterARP_port2)
        + "\n\t\tIP:" + std::to_string(counterIP_port2)
        + "\n\t\tTCP:" + std::to_string(counterTCP_port2)
        + "\n\t\tUDP:" + std::to_string(counterUDP_port2)
        + "\n\t\tICMP:" + std::to_string(counterICMP_port2)
        + "\n\t\tHTTP:" + std::to_string(counterHTTP_port2)
        + "\n\tport1 OUT:"
        "\n\t\tEthernetII: " + std::to_string(counterEthernetII_port1)
        + "\n\t\tARP:" + std::to_string(counterARP_port1)
        + "\n\t\tIP:" + std::to_string(counterIP_port1)
        + "\n\t\tTCP:" + std::to_string(counterTCP_port1)
        + "\n\t\tUDP:" + std::to_string(counterUDP_port1)
        + "\n\t\tICMP:" + std::to_string(counterICMP_port1)
        + "\n\t\tHTTP:" + std::to_string(counterHTTP_port1)
        + "\n\tport2 IN:"
        "\n\t\tEthernetII: " + std::to_string(counterEthernetII_port1)
        + "\n\t\tARP:" + std::to_string(counterARP_port1)
        + "\n\t\tIP:" + std::to_string(counterIP_port1)
        + "\n\t\tTCP:" + std::to_string(counterTCP_port1)
        + "\n\t\tUDP:" + std::to_string(counterUDP_port1)
        + "\n\t\tICMP:" + std::to_string(counterICMP_port1)
        + "\n\t\tHTTP:" + std::to_string(counterHTTP_port1)
        + "\n\tport2 OUT:"
        "\n\t\tEthernetII: " + std::to_string(counterEthernetII_port2)
        + "\n\t\tARP:" + std::to_string(counterARP_port2)
        + "\n\t\tIP:" + std::to_string(counterIP_port2)
        + "\n\t\tTCP:" + std::to_string(counterTCP_port2)
        + "\n\t\tUDP:" + std::to_string(counterUDP_port2)
        + "\n\t\tICMP:" + std::to_string(counterICMP_port2)
        + "\n\t\tHTTP:" + std::to_string(counterHTTP_port2)
    ));

    std::string cam_table_string;
    std::map<std::string, std::map<int, int> >::iterator itr;
    std::map<int, int>::iterator ptr;
    
    for (itr = cam_table.begin(); itr != cam_table.end(); itr++) {

        for (ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
            cam_table_string += "|MAC: " + itr->first + "  |PORT: " + std::to_string(ptr->first) + "  |AGING: " + std::to_string(ptr->second) + "|\n";
        }
    }
   
    this->ui.textEdit_2->setText(QString::fromStdString(
        cam_table_string
    )); 
}

bool PSIPMLSW::callback_port1(PDU& pdu) {
    std::lock_guard<std::mutex> lock(this->threadMutex);

    try {
        EthernetII* ether = pdu.find_pdu<EthernetII>();

        uint current_hash = qHash(ether, 0);
        if (hash_port1.contains(current_hash)) {
            qDebug() << current_hash;
            return true;
        }
        else {
            hash_port2.insert(current_hash, 1);
        }


        if (ether) {
            HWAddress<6> src_mac = ether->src_addr();
            HWAddress<6> dst_mac = ether->dst_addr();
            TCP* tcp = pdu.find_pdu<TCP>();
            ARP* arp = pdu.find_pdu<ARP>();
            IP* ip = pdu.find_pdu<IP>();
            ICMP* icmp = pdu.find_pdu<ICMP>();
            UDP* udp = pdu.find_pdu<UDP>();

            clock_t startTime = clock(); //Start timer
            int secondsPassed;


            mutex.lock();
            int cam_table_size = cam_table.size();
            bool is_in_table = false;

            std::map<std::string, std::map<int, int> >::iterator itr;
            std::map<int, int>::iterator ptr;

            if (cam_table_size == 0) {
                cam_table.insert(std::make_pair(src_mac.to_string(), std::map<int, int>()));
                cam_table[src_mac.to_string()].insert(std::make_pair(1, aging));
            }
            else {
                for (itr = cam_table.begin(); itr != cam_table.end(); itr++) {
                    for (ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
                        if (src_mac.to_string() == itr->first) {
                            is_in_table = true;
                            ptr->second = aging;
                            break;
                        }
                    }
                }
                if (is_in_table == false) {
                    cam_table.insert(std::make_pair(src_mac.to_string(), std::map<int, int>()));
                    cam_table[src_mac.to_string()].insert(std::make_pair(1, aging));
                }
            }

            mutex.unlock();

            if (ether != NULL)
                counterEthernetII_port1++;
            if (tcp != NULL) {
                if (tcp->dport() == 80)
                    counterHTTP_port1++;
                counterTCP_port1++;
            }
            if (arp != NULL)
                counterARP_port1++;
            if (ip != NULL)
                counterIP_port1++;
            if (icmp != NULL)
                counterICMP_port1++;
            if (udp != NULL)
                counterUDP_port1++;
            
            PacketSender sender;
            if (dst_mac.to_string() == "ff:ff:ff:ff:ff:ff") {
                sender.send(pdu, "{E0160574-F78F-4A39-9E69-B7A4257D3D4E}");
            }
            else {
                auto index = cam_table.find(dst_mac.to_string());
                if (index != cam_table.end()) { //ak je v cam tabulke
                    if(index->second.begin()->first == 2)
                        sender.send(pdu, "{E0160574-F78F-4A39-9E69-B7A4257D3D4E}");
                }
                else {
                    sender.send(pdu, "{E0160574-F78F-4A39-9E69-B7A4257D3D4E}");
                }
            }

        }

        return true;
    }
    catch (const std::exception&) {
        return true;
    }
    
    return true;

    
}

void PSIPMLSW::port1() // {50545B66-1647-409C-991F-8FF8FE68A1B9}
{
    NetworkInterface port1("{50545B66-1647-409C-991F-8FF8FE68A1B9}");
    Sniffer sniffer(port1.name());
    
    sniffer.sniff_loop(
        std::bind(
            &PSIPMLSW::callback_port1,
            this, std::placeholders::_1
        )
    );
}

bool PSIPMLSW::callback_port2(PDU& pdu) {
    std::lock_guard<std::mutex> lock(this->threadMutex);
    PDU* cloned_pdu = pdu.clone();

    try {
        EthernetII* ether = pdu.find_pdu<EthernetII>();

        uint current_hash = qHash(ether, 0);
        if (hash_port2.contains(current_hash)) {
            qDebug() << current_hash;
            return true;
        }
        else {
            hash_port1.insert(current_hash, 1);
        }

        if (ether) {
            TCP* tcp = pdu.find_pdu<TCP>();
            ARP* arp = pdu.find_pdu<ARP>();
            IP* ip = pdu.find_pdu<IP>();
            ICMP* icmp = pdu.find_pdu<ICMP>();
            UDP* udp = pdu.find_pdu<UDP>();
            HWAddress<6> src_mac = ether->src_addr();
            HWAddress<6> dst_mac = ether->dst_addr();

            clock_t startTime = clock(); //Start timer
            int secondsPassed;

            mutex.lock();
            int cam_table_size = cam_table.size();
            bool is_in_table = false;

            std::map<std::string, std::map<int, int> >::iterator itr;
            std::map<int, int>::iterator ptr;

            if (cam_table_size == 0) {
                cam_table.insert(std::make_pair(src_mac.to_string(), std::map<int, int>()));
                cam_table[src_mac.to_string()].insert(std::make_pair(2, aging));
            }
            else {
                for (itr = cam_table.begin(); itr != cam_table.end(); itr++) {
                    for (ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
                        if (src_mac.to_string() == itr->first) {
                            is_in_table = true;
                            ptr->second = aging;
                            break;
                        }
                    }
                }
                if (is_in_table == false) {
                    cam_table.insert(std::make_pair(src_mac.to_string(), std::map<int, int>()));
                    cam_table[src_mac.to_string()].insert(std::make_pair(2, aging));
                }
            }
            mutex.unlock();
            if (ether != NULL)
                counterEthernetII_port2++;
            if (tcp != NULL) {
                if (tcp->dport() == 80)
                    counterHTTP_port2++;
                counterTCP_port2++;
            }
                
            if (arp != NULL)
                counterARP_port2++;
            if (ip != NULL)
                counterIP_port2++;
            if (icmp != NULL)
                counterICMP_port2++;
            if (udp != NULL)
                counterUDP_port2++;

            PacketSender sender;
            if (dst_mac.to_string() == "ff:ff:ff:ff:ff:ff") {
                sender.send(pdu, "{50545B66-1647-409C-991F-8FF8FE68A1B9}");
            }
            else {
                auto index = cam_table.find(dst_mac.to_string());
                if (index != cam_table.end()) { //ak je v cam tabulke
                    if (index->second.begin()->first == 1)
                        sender.send(pdu, "{50545B66-1647-409C-991F-8FF8FE68A1B9}");
                }
                else {
                    sender.send(pdu, "{50545B66-1647-409C-991F-8FF8FE68A1B9}");
                }
            }

            return true;
        }
    }
    catch (const std::exception&){
        return true;
    }
    return true;
}

void PSIPMLSW::port2() //{E0160574-F78F-4A39-9E69-B7A4257D3D4E}
{
    NetworkInterface port2("{E0160574-F78F-4A39-9E69-B7A4257D3D4E}");
    Sniffer sniffer(port2.name());

    sniffer.sniff_loop(
        std::bind(
            &PSIPMLSW::callback_port2,
            this, std::placeholders::_1
        )
    );
}

void PSIPMLSW::buffer() {
    while (1) {
        this->myQthread.start();
        this->myQthread.quit();
    }
}

void analyze(PSIPMLSW *sw) {
    
    std::thread th1(&PSIPMLSW::port1, sw);
    std::thread th2(&PSIPMLSW::port2, sw);
    std::thread th3(&PSIPMLSW::timer, sw);

    th1.detach();
    th2.detach();
    th3.detach();
}

void PSIPMLSW::clear() {
    counterEthernetII_port1 = 0;
    counterEthernetII_port2 = 0;
    counterARP_port1 = 0;
    counterARP_port2 = 0;
    counterIP_port1 = 0;
    counterIP_port2 = 0;
    counterICMP_port1 = 0;
    counterICMP_port2 = 0;
    counterHTTP_port1 = 0;
    counterHTTP_port2 = 0;
    counterTCP_port1 = 0;
    counterTCP_port2 = 0;
    counterUDP_port1 = 0;
    counterUDP_port2 = 0;
    cam_table.clear();
}

void PSIPMLSW::start() {
    QPushButton* button = (QPushButton*)sender();
    analyze(this);
}



