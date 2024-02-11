#include "pcap_interface.h"
int main(int argc, char** argv){
    
    if(argc == 2 || argc == 3){
        pcap_interface ex;
        ex.exit_signal_capture();
        if(ex.open_file(argv[1]) == 0){
            ex.watch_all_packets(0,1);
            ex.output_data(argv[1]);
        }
        else{
            std::string device_name = ex.find_device_name(argv[1]);
            if(device_name == "")
                return -1;
            
            if(ex.open_live(device_name) == 0){
                int packets_number = 0;
                if(argc == 3){
                    try{
                        std::string str_packets_number = argv[2];
                        packets_number = std::stoi(str_packets_number);
                    }
                    catch(...){
                        std::cout<<"Invalid 2'nd argument"<<std::endl;
                        return -1;
                    }
                }
                ex.watch_all_packets(packets_number,0);
                ex.output_data(device_name);
            }
        }
    }
    else
        std::cout<<"Invalid arguments"<<std::endl;
    return 0;
}