#include "pcap_interface.h"
bool pcap_interface::break_flag = false;
pcap_interface::pcap_interface(){
    error_buffer = new char[PCAP_ERRBUF_SIZE];
}
pcap_interface::~pcap_interface(){
    delete error_buffer;
    if(handle != NULL)
        pcap_close(handle);
}
int8_t pcap_interface::open_file(const std::string& file_path){
    std::cout<<"Trying to open "<<file_path<<std::endl;
    handle = pcap_open_offline(file_path.c_str(), error_buffer);
    if(handle != NULL){
        std::cout<<file_path<<" was opened"<<std::endl;
        return 0;
    }
    std::cout<<error_buffer<<std::endl;
    return -1;
}
int8_t pcap_interface::open_live(const std::string& device_name){
    std::cout<<"Trying to capture "<<device_name<<std::endl;
    handle = pcap_open_live(device_name.c_str(),BUFSIZ,0,1000,error_buffer);
    if(handle != NULL){
        std::cout<<device_name<<" is listenning..."<<std::endl;
        return 0;
    }
    std::cout<<error_buffer<<std::endl;
    return -1;
}

int pcap_interface::watch_all_packets(const int& packets_number, bool hide_output){
    struct args user_args;
    user_args.hide_output = hide_output;
    user_args.handle = handle;
    user_args.main_cont = &main_cont; 
    return pcap_loop(handle, packets_number, packet_handler, (u_char*)&user_args);
}

std::string pcap_interface::find_device_name(const std::string& device_name_to_find)const{
    std::cout<<"Trying to find "<<device_name_to_find<<std::endl;
    pcap_if_t *interfaces;
    if(pcap_findalldevs(&interfaces,error_buffer)==-1){
        std::cout<<error_buffer<<std::endl;
        return "";   
    }

    for(pcap_if_t* tmp=interfaces;tmp!=NULL;tmp=tmp->next)
        if(std::string(tmp->name) == device_name_to_find)
            return device_name_to_find;
    std::cout<<device_name_to_find<<" was not found"<<std::endl;
    return "";
}
void pcap_interface::output_data(const std::string& file_path)const{
    std::string result_path = file_path+".csv";
    std::ofstream outfile(result_path);
    if(!outfile.is_open()){
        std::cout<<"Error in opening output file"<<std::endl;
    }
    outfile<<"Source IP,Destination IP,Source port,Destination port,Packets sum,Bytes sum"<<std::endl;
    for (const auto& element : main_cont)
        outfile << element.first << "," << element.second.first<<","<<element.second.second << std::endl;
    outfile.close();
    if(outfile.good()){
        std::cout<<"Result was written to "<< result_path<<std::endl;
    }
}
void pcap_interface::exit_signal_capture(){
    struct sigaction sa;
    memset( &sa, 0, sizeof(sa));
    sa.sa_handler = [](int) {break_flag = true;std::cout<<std::endl;};
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL);
}

void pcap_interface::packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_ptr){
    struct args* user_args = (struct args*)args;
    if(break_flag == true)
        pcap_breakloop(user_args->handle);

    struct ether_header *eth_header = (struct ether_header *) packet_ptr;
    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        return;

    const u_char *ip_header_ptr = (const u_char *)(packet_ptr+sizeof(struct ether_header));
    struct iphdr* ip_header = (struct iphdr*)ip_header_ptr;
    
    if(ip_header->version == 6 || ip_header->protocol!= IPPROTO_TCP && ip_header->protocol != IPPROTO_UDP)
        return;

    struct in_addr ip_addr;
    ip_addr.s_addr = ip_header->saddr;
    std::string source_ip = inet_ntoa(ip_addr);
    ip_addr.s_addr = ip_header->daddr;
    std::string dest_ip = inet_ntoa(ip_addr);
    
    std::string source_port, dest_port;
    int l4_header_length;
    switch(ip_header->protocol){
        case IPPROTO_TCP:{
            std::cout<<"TCP ";
            struct tcphdr* tcp_header = (struct tcphdr*)(packet_ptr+ip_header->ihl*4+sizeof(struct ether_header));
            l4_header_length = tcp_header->doff*4;
            source_port = std::to_string(ntohs(tcp_header->source));
            dest_port = std::to_string(ntohs(tcp_header->dest));
            break;
        }
        case IPPROTO_UDP:{
            std::cout<<"UDP ";
            struct udphdr* udp_header = (struct udphdr*)(packet_ptr+ip_header->ihl*4+sizeof(struct ether_header));
            l4_header_length = sizeof(struct udphdr);
            source_port = std::to_string(ntohs(udp_header->source));
            dest_port = std::to_string(ntohs(udp_header->dest));
            break;
        }
        default:
            return;
    }
    int payload_length = header->caplen - sizeof(struct ether_header) - ip_header->ihl*4 - l4_header_length;
    std::string thread = source_ip+","+dest_ip+","+source_port+","+dest_port;
    
    std::unordered_map<std::string,std::pair<int,int>>*main_cont_ptr = (std::unordered_map<std::string,std::pair<int,int>>*)user_args->main_cont;
    main_cont_ptr->operator[](thread) = std::make_pair(main_cont_ptr->operator[](thread).first+1,main_cont_ptr->operator[](thread).second+payload_length);
    
    if(user_args->hide_output == 0)
        std::cout<<source_ip<<"\t"<<dest_ip<<"\t"<<source_port<<"\t"<<dest_port<<"\t"<<payload_length<<std::endl;
    return;
}
