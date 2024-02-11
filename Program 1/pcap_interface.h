#pragma once
#include <iostream>
#include <string>
#include <unordered_map>
#include <pcap.h>
#include <fstream>
#include <signal.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
class pcap_interface{
    struct args{
        bool hide_output;
        pcap_t* handle;
        std::unordered_map<std::string,std::pair<int,int>>* main_cont;
    };
    private: 
        pcap_t* handle;
        std::unordered_map<std::string,std::pair<int,int>> main_cont;
        char* error_buffer;
    public:
        static bool break_flag;
        pcap_interface();
        ~pcap_interface();
        int8_t open_file(const std::string& file_path);
        int8_t open_live(const std::string& device_name);
        int watch_all_packets(const int& packets_number,bool hide_output);
        std::string find_device_name(const std::string& device_name_to_find)const;
        void output_data(const std::string& file_path)const;
        static void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_ptr);
        void exit_signal_capture();
};


