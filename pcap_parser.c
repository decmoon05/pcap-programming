/*
 * pcap_parser.c
 * PCAP API 로 TCP 패킷을 잡아서 이더넷, IP, TCP 헤더와 HTTP 메시지를 출력한다.
 * 제공받은 sniff_improved.c 와 myheader.h 를 바탕으로 got_packet 을 확장했다.
 *
 * gcc -o pcap_parser pcap_parser.c -lpcap
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pcap.h>

/* 이더넷 헤더 */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* IP 헤더 (myheader.h) */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* TCP 헤더 (myheader.h) */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th)  (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

int count = 0;

void print_mac(const u_char *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    count++;
    printf("\n[Packet #%d]\n", count);

    struct ethheader *eth = (struct ethheader *)packet;
    printf("[Ethernet] Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n           Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");

    if (ntohs(eth->ether_type) != 0x0800)   /* IP 아니면 스킵 */
        return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    /* inet_ntoa 는 내부 버퍼를 재사용해서 한 줄에 두 번 부르면 값이 겹친다. 따로 출력. */
    printf("[IP]       Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("           Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    /* IP 헤더는 길이가 가변이라 ihl 에 4를 곱해서 바이트로 만든다. */
    int ip_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_len);
    printf("[TCP]      Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("           Dst Port: %d\n", ntohs(tcp->tcp_dport));

    /* TCP 헤더 뒤가 HTTP 메시지. 여기도 오프셋에 4를 곱한다. */
    int tcp_len = TH_OFF(tcp) * 4;
    const u_char *http = (u_char *)tcp + tcp_len;
    int http_len = (int)header->caplen - (int)(http - packet);

    if (http_len > 0) {
        printf("[HTTP]     Message (%d bytes):\n", http_len);
        int i;
        for (i = 0; i < http_len; i++) {
            if (http[i] == '\r')
                continue;
            else if (http[i] == '\n' || isprint(http[i]))
                putchar(http[i]);
            else
                putchar('.');
        }
        printf("\n");
    } else {
        printf("[HTTP]     (데이터 없음)\n");
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;

    /* 인자로 pcap 파일을 주면 그 파일을 읽고, 없으면 eth0 에서 직접 잡는다. */
    if (argc > 1)
        handle = pcap_open_offline(argv[1], errbuf);
    else
        handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        printf("open error: %s\n", errbuf);
        return -1;
    }
    printf("캡처 시작 (tcp 만)\n");

    pcap_compile(handle, &fp, "tcp", 0, 0);   /* tcp 만 잡기 */
    pcap_setfilter(handle, &fp);

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
