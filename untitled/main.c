#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iniparser.h>



// 由于data_offset、reserved和flags是位字段，我们需要从header_length_and_flags中提取它们
#define TCP_DATA_OFFSET_MASK 0xF0
#define TCP_RESERVED_MASK    0x0C
#define TCP_FLAGS_MASK       0x3F

typedef struct {
    int packet_count;  // 包计数
    int total_bytes;   // 流量大小
} stats_t;

stats_t stats = {0,0}; // 全局统计变量

// 以太网头部结构体
typedef struct ether_header {
    u_char ether_dhost[6];    // 目的MAC地址
    u_char ether_shost[6];    // 源MAC地址
    u_short ether_type;       // 协议类型（例如，IPv4是0x0800）
} ether_header;

// IP数据报头部结构体
typedef struct ip_header {
    u_int8_t  iph_verhlen;    // 版本(4位), 头部长度(4位)
    u_int8_t  iph_tos;        // 服务类型
    u_int16_t iph_len;        // 总长度
    u_int16_t iph_id;         // 标识
    u_int16_t iph_fragoff;    // 分段偏移
    u_int8_t  iph_ttl;        // 生存时间
    u_int8_t  iph_protocol;   // 协议
    u_int16_t iph_check;      // 头部校验和
    u_int8_t iph_sourceip[4];   // 源IP地址
    u_int8_t iph_destip[4];     // 目标IP地址
} ip_header;

//ARP数据报头部结构体
typedef struct arp_header{
    u_int16_t arp_hardware_type;
    u_int16_t arp_protocol_type;
    u_int8_t arp_hardware_length;
    u_int8_t arp_protocol_length;
    u_int16_t arp_operation_code;
    u_int8_t arp_source_eth_address[6];
    u_int8_t arp_source_eth_ip[4];
    u_int8_t arp_destination_eth_address[6];
    u_int8_t arp_destination_eth_ip[4];
}arp_header;

//UDP数据报头部结构体
typedef struct udp_header{
    u_int16_t udp_source_port;
    u_int16_t udp_destination_port;
    u_int16_t udp_length;
    u_int16_t udp_checksum;
}udp_header;

//TCP数据报头部结构体
typedef struct tcp_header{
    u_int16_t tcp_source_port;
    u_int16_t tcp_destination_port;
    u_int32_t sequence_number;   // 序列号
    u_int32_t acknowledgment_number; // 确认号
//    u_int8_t data_offset : 4;        // 数据偏移（以4字节为单位）
//    u_int8_t reserved : 6;           // 保留位
//    u_int8_t flags : 6;              // 控制位（URG, ACK, PSH, RST, SYN, FIN）
    u_int8_t header_length_and_flags; // 联合了data_offset、reserved和flags
    u_int16_t window_size;           // 窗口大小
    u_int16_t tcp_checksum;              // 校验和
    u_int16_t urgent_pointer;        // 紧急指针
}tcp_header;

//ICMP数据报头部结构体
typedef struct icmp_header{
    u_int8_t icmp_type;       // ICMP类型
    u_int8_t icmp_code;       // ICMP代码
    u_int16_t icmp_checksum;  // ICMP校验和
}icmp_header;


// 回调函数，用于处理捕获到的数据包
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {


    stats.packet_count++;
    stats.total_bytes += pkthdr->len;

    const ether_header *eth;
    const ip_header *ip;
    const arp_header *arp;
    const udp_header *udp;
    const tcp_header *tcp;
    const icmp_header *icmp;

    eth = (const ether_header *)packet;
    // 跳过以太网头部，找到IP头部
    ip = (const ip_header *)(packet + sizeof(ether_header));
    // 跳过以太网头部，找到ARP头部
    arp = (const arp_header *)(packet + sizeof(ether_header));
    // 跳过以太网头部和IP头部，找到UDP头部
    udp = (const udp_header *)(packet + sizeof(ether_header) + sizeof(ip_header));
    // 跳过以太网头部和IP头部，找到TCP头部
    tcp = (const tcp_header *)(packet + sizeof(ether_header) + sizeof(ip_header));
    // 跳过以太网头部和IP头部，找到ICMP头部
    icmp = (const icmp_header *)(packet + sizeof(ether_header) + sizeof(ip_header));



    // 输出以太网头部字段
    printf("Ethernet header:\n");
    printf("  Destination MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", eth->ether_dhost[i]);
    }
    printf("\n");
    printf("  Source MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", eth->ether_shost[i]);
    }
    printf("\n");
    printf("  EtherType: 0x%04x\n", ntohs(eth->ether_type));
    switch(ntohs(eth->ether_type)){
        case 0x0800:
            // 输出IP数据报头部字段
            printf("IP header:\n");
            printf("  Version: %d\n", ip->iph_verhlen >> 4);
            printf("  Header length: %d bytes\n", (ip->iph_verhlen & 0x0F) * 4);
            printf("  TOS: 0x%02x\n", ip->iph_tos);
            printf("  Total length: %d bytes\n", ntohs(ip->iph_len));
            printf("  ID: %d\n", ntohs(ip->iph_id));
            printf("  Fragment offset: %d\n", ntohs(ip->iph_fragoff) & 0x1FFF);
            printf("  TTL: %d\n", ip->iph_ttl);
            printf("  Protocol: %d\n", ip->iph_protocol);
            printf("  Checksum: 0x%04x\n", ntohs(ip->iph_check));
            printf("  Source IP: ");
            for (int i = 0; i < 4; i++) {
                printf("%d ", ip->iph_sourceip[i]);
            }
            printf("\n");
            printf("  Destination IP: ");
            for (int i = 0; i < 4; i++) {
                printf("%d ", ip->iph_destip[i]);
            }
            switch (ip->iph_protocol) {
                case 0x06:
                    // 输出TCP数据报头部字段
                    printf("\nTCP Header:\n");
                    printf("  Source Port: %u\n", ntohs(tcp->tcp_source_port));
                    printf("  Destination Port: %u\n", ntohs(tcp->tcp_destination_port));
                    printf("  Sequence Number: %u\n", ntohl(tcp->sequence_number));
                    printf("  Acknowledgment Number: %u\n", ntohl(tcp->acknowledgment_number));
                    // 提取数据偏移（以4字节为单位）
                    unsigned int data_offset = (tcp->header_length_and_flags & TCP_DATA_OFFSET_MASK) >> 4;
                    printf("  Data Offset (in 4-byte words): %u\n", data_offset);

                    // 提取保留位（这里只是打印，但通常这些位不被使用）
                    unsigned int reserved = (tcp->header_length_and_flags & TCP_RESERVED_MASK) >> 2;
                    // 通常情况下，你不会关心这些保留位的具体值，除非你正在调试或实现特定的TCP功能
                    printf("  Reserved Bits: %u\n", reserved);

                    // 提取控制位（URG, ACK, PSH, RST, SYN, FIN）
                    unsigned int flags = tcp->header_length_and_flags & TCP_FLAGS_MASK;
                    printf("  Flags: ");
                    if (flags & (1 << 5)) printf("URG ");
                    if (flags & (1 << 4)) printf("ACK ");
                    if (flags & (1 << 3)) printf("PSH ");
                    if (flags & (1 << 2)) printf("RST ");
                    if (flags & (1 << 1)) printf("SYN ");
                    if (flags & (1 << 0)) printf("FIN ");
                    printf("\n");
                    printf("  Window Size: %u\n", ntohs(tcp->window_size));
                    printf("  Checksum: 0x%04X\n", ntohs(tcp->tcp_checksum));
                    printf("  Urgent Pointer: %u\n", tcp->urgent_pointer);
                    // 假设tcp是指向TCP头部的指针
                    // 假设也有tn->tcp_source_port和tn->tcp_destination_port的相关数据

                    if (ntohs(tcp->tcp_source_port) == 80 || ntohs(tcp->tcp_destination_port) == 80) {
                        printf("Protocol: HTTP\n");
                    } else if (ntohs(tcp->tcp_source_port) == 443 || ntohs(tcp->tcp_destination_port) == 443) {
                        printf("Protocol: HTTPS\n");
                    } else if (ntohs(tcp->tcp_source_port) == 21 || ntohs(tcp->tcp_destination_port) == 21) {
                        printf("Protocol: FTP\n");
                    } else if (ntohs(tcp->tcp_source_port) == 22 || ntohs(tcp->tcp_destination_port) == 22) {
                        printf("Protocol: SSH\n");
                    } else if (ntohs(tcp->tcp_source_port) == 23 || ntohs(tcp->tcp_destination_port) == 23) {
                        printf("Protocol: Telnet\n");
                    } else if (ntohs(tcp->tcp_source_port) == 25 || ntohs(tcp->tcp_destination_port) == 25) {
                        printf("Protocol: SMTP\n");
                    } else if (ntohs(tcp->tcp_source_port) == 110 || ntohs(tcp->tcp_destination_port) == 110) {
                        printf("Protocol: POP3\n");
                    } else if (ntohs(tcp->tcp_source_port) == 143 || ntohs(tcp->tcp_destination_port) == 143) {
                        printf("Protocol: IMAP\n");
                    } else {
                        printf("Protocol: Unknown or Other TCP Protocol\n");
                    }
                break;
                case 0x11:
                    // 输出UDP数据报头部字段
                    printf("\n");
                    printf("UDP header:\n");
                    printf("  Source Port:%d\n",ntohs(udp->udp_source_port));
                    printf("  Destination Port:%d\n",ntohs(udp->udp_destination_port));
                    printf("  Length:%d\n",ntohs(udp->udp_length));
                    printf("  Checksum:0x%04x\n",ntohs(udp->udp_checksum));
                    // 假设udp是指向UDP头部的指针
                    // 假设也有udp->udp_source_port和udp->udp_destination_port的相关数据

                    if (ntohs(udp->udp_source_port) == 53 || ntohs(udp->udp_destination_port) == 53) {
                        printf("Protocol: DNS\n");
                    } else if (ntohs(udp->udp_source_port) == 67 || ntohs(udp->udp_destination_port) == 67) {
                        printf("Protocol: DHCP (Server)\n");
                    } else if (ntohs(udp->udp_source_port) == 68 || ntohs(udp->udp_destination_port) == 68) {
                        printf("Protocol: DHCP (Client)\n");
                    } else if (ntohs(udp->udp_source_port) == 69 || ntohs(udp->udp_destination_port) == 69) {
                        printf("Protocol: TFTP\n");
                    } else if (ntohs(udp->udp_source_port) == 123 || ntohs(udp->udp_destination_port) == 123) {
                        printf("Protocol: NTP\n");
                    } else {
                        printf("Protocol: Unknown or Other UDP Protocol\n");
                    }
                break;

                case 0x01:
                    // 输出ICMP数据报头部字段
                    printf("\nICMP Header:\n");
                    printf("  Type: %u\n", icmp->icmp_type);
                    printf("  Code: %u\n", icmp->icmp_code);
                    printf("  Checksum: 0x%04X\n", ntohs(icmp->icmp_checksum));
                break;
            }
            break;
        case 0x0806:
            // 输出ARP数据报头部字段
            printf("ARP header:\n");
            printf("  ARP Hardware Type: 0x%04X\n", arp->arp_hardware_type);
            printf("  ARP Protocol Type: 0x%04X\n", arp->arp_protocol_type);
            printf("  ARP Hardware Length: %u\n", arp->arp_hardware_length);
            printf("  ARP Protocol Length: %u\n", arp->arp_protocol_length);
            printf("  ARP Operation Code: 0x%04X\n", arp->arp_operation_code);

            printf("  ARP Source Ethernet Address: ");
            for (int i = 0; i < 6; i++) {
               printf("%02X:", arp->arp_source_eth_address[i]);
            }
            printf("\b \n"); // 删除最后一个冒号后的空格

            printf("  ARP Source IP Address: %u.%u.%u.%u\n",
                  arp->arp_source_eth_ip[0],
                  arp->arp_source_eth_ip[1],
                  arp->arp_source_eth_ip[2],
                  arp->arp_source_eth_ip[3]);

            printf("  ARP Destination Ethernet Address: ");
            for (int i = 0; i < 6; i++) {
                printf("%02X:", arp->arp_destination_eth_address[i]);
            }
            printf("\b \n"); // 删除最后一个冒号后的空格

            printf("  ARP Destination IP Address: %u.%u.%u.%u\n",
                  arp->arp_destination_eth_ip[0],
                  arp->arp_destination_eth_ip[1],
                  arp->arp_destination_eth_ip[2],
                  arp->arp_destination_eth_ip[3]);
            break;
        }
    pcap_dumper_t *dumpfile = (pcap_dumper_t *)user;
    // 保存数据包
    pcap_dump((u_char *)dumpfile, pkthdr, packet);
}

int main() {
    pcap_t *handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    /*bpf过滤规则*/
    bpf_u_int32 net_ip;
    /* 网络地址*/
    pcap_dumper_t *dumpfile = NULL;


    // 加载INI文件
    dictionary *ini = iniparser_load("./llz.ini");
    if (ini == NULL) {
        printf("Cannot load INI file\n");
        return 1;
    }

    // 读取值
    const char *device = iniparser_getstring(ini, "Setting:device", "default_device");
    const char *filepath = iniparser_getstring(ini, "Setting:filepath", "null");
    const char *rule = iniparser_getstring(ini, "Setting:rule", "tcp");
    const char *outfile = iniparser_getstring(ini, "Setting:outfile", "default");
    int liveoroff = iniparser_getint(ini, "Setting:liveoroff", 0);

    if (liveoroff == 0) {
        handle = pcap_open_offline(filepath,error_content);
    } else {
        handle = pcap_open_live(device, BUFSIZ, 1, 0, error_content);
        /* 打开网络接口*/
    }
    if (handle == NULL) {
        printf( "无法打开设备 %s: %s\n", device, error_content);
        return 1;
    }
    pcap_compile(handle, &bpf_filter,rule , 0, net_ip);
    /*编译BPF过滤规则 */
    pcap_setfilter(handle, &bpf_filter);
    /*设置过滤规则*/

    dumpfile = pcap_dump_open(handle, outfile);
    pcap_loop(handle, -1,packet_handler, (u_char *)dumpfile);
    /*循环捕获*/
    // 打印统计信息
    printf("捕获到的包数量: %u\n",stats.packet_count);
    printf("总流量大小: %u\n",stats.total_bytes);

    pcap_dump_close(dumpfile);
    /*关闭dumpfile*/


    pcap_close(handle);
    iniparser_freedict(ini);

    return 0;
}

