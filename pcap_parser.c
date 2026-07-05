/*
 * pcap_parser.c
 *
 * libpcap(PCAP API)로 TCP 패킷을 캡처해서 각 계층의 헤더를 순서대로 파싱한다.
 * 이더넷 -> IP -> TCP 순으로 헤더를 벗겨내고, 그 뒤에 오는 HTTP 메시지까지 출력한다.
 * 강의에서 제공받은 sniff_improved.c 와 myheader.h 의 구조체를 바탕으로,
 * 맥 주소, 포트, HTTP 메시지 출력 부분을 직접 붙여서 확장했다.
 *
 * 빌드   : gcc -Wall -o pcap_parser pcap_parser.c -lpcap
 * 실행(파일): ./pcap_parser -r http.pcap
 * 실행(라이브): sudo ./pcap_parser -i eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>   /* IPPROTO_TCP */
#include <arpa/inet.h>    /* inet_ntoa, ntohs */
#include <pcap.h>

/* 이더넷 헤더는 목적지 맥 6, 출발지 맥 6, 타입 2 로 항상 14바이트 고정이다. */
#define ETHER_HDR_LEN 14

/* --- 아래 세 구조체는 제공받은 myheader.h 의 정의를 그대로 가져와 주석만 정리했다. --- */

/* 이더넷 헤더 */
struct ethheader {
    u_char  ether_dhost[6];   /* 목적지 맥 주소 */
    u_char  ether_shost[6];   /* 출발지 맥 주소 */
    u_short ether_type;       /* 다음 계층 타입. 0x0800 이면 IPv4 */
};

/* IP 헤더. 첫 바이트가 4비트 헤더길이(ihl) + 4비트 버전(ver) 이라서 비트필드로 쪼갠다.
 * x86 은 리틀엔디언이라 먼저 선언한 iph_ihl 이 하위 4비트(= 헤더길이)에 들어간다. */
struct ipheader {
    unsigned char      iph_ihl:4,     /* 헤더 길이. 4바이트 단위 개수 */
                       iph_ver:4;     /* IP 버전 */
    unsigned char      iph_tos;       /* 서비스 타입 */
    unsigned short int iph_len;       /* 전체 길이. IP헤더 + 그 뒤 데이터 */
    unsigned short int iph_ident;     /* 식별자 */
    unsigned short int iph_flag:3,    /* 플래그 */
                       iph_offset:13; /* 프래그먼트 오프셋 */
    unsigned char      iph_ttl;       /* TTL */
    unsigned char      iph_protocol;  /* 상위 프로토콜. 6 이면 TCP */
    unsigned short int iph_chksum;    /* 체크섬 */
    struct  in_addr    iph_sourceip;  /* 출발지 IP */
    struct  in_addr    iph_destip;    /* 목적지 IP */
};

/* TCP 헤더 */
struct tcpheader {
    u_short tcp_sport;   /* 출발지 포트 */
    u_short tcp_dport;   /* 목적지 포트 */
    u_int   tcp_seq;     /* 시퀀스 번호 */
    u_int   tcp_ack;     /* ACK 번호 */
    u_char  tcp_offx2;   /* 상위 4비트가 데이터 오프셋(= TCP 헤더 길이) */
#define TH_OFF(th)  (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;   /* 제어 플래그 (SYN, ACK, FIN 등) */
    u_short tcp_win;     /* 윈도우 크기 */
    u_short tcp_sum;     /* 체크섬 */
    u_short tcp_urp;     /* 긴급 포인터 */
};

static int packet_count = 0;

/* 맥 주소 6바이트를 사람이 읽는 형태로 찍는다. */
static void print_mac(const u_char *m)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* HTTP 메시지(애플리케이션 데이터)를 텍스트로 찍는다.
 * HTTP 헤더는 CRLF 로 줄을 나누는데, 화면에서 보기 좋게 CR 은 버리고 LF 만 줄바꿈으로 쓴다.
 * 그 외에 출력 불가능한 바이트는 점으로 바꿔서 깨지지 않게 한다. */
static void print_payload(const u_char *data, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = data[i];
        if (c == '\r')
            continue;
        else if (c == '\n')
            putchar('\n');
        else if (isprint(c))
            putchar(c);
        else
            putchar('.');
    }
    if (len > 0 && data[len - 1] != '\n')
        putchar('\n');
}

/* pcap_loop 이 패킷을 하나 잡을 때마다 부르는 콜백.
 * 여기서 프레임을 앞에서부터 한 겹씩 벗겨가며 파싱한다. */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    packet_count++;
    printf("\n[Packet #%d]\n", packet_count);

    /* 1. 이더넷 계층. 캡처된 프레임 맨 앞이 이더넷 헤더다. */
    struct ethheader *eth = (struct ethheader *)packet;

    printf("[Ethernet] Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n           Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");

    /* 타입이 IPv4(0x0800) 가 아니면 위 계층을 우리가 정한 규칙대로 못 읽으니 여기서 멈춘다.
     * 이더넷 타입은 네트워크 바이트 순서(빅엔디언)라서 ntohs 로 뒤집어 읽는다. */
    if (ntohs(eth->ether_type) != 0x0800) {
        printf("           (IPv4 가 아니라 스킵)\n");
        return;
    }

    /* 2. IP 계층. 이더넷 헤더(14바이트) 바로 다음이 IP 헤더 시작이다. */
    struct ipheader *ip = (struct ipheader *)(packet + ETHER_HDR_LEN);

    /* inet_ntoa 는 내부의 static 버퍼 하나를 계속 재사용한다.
     * 그래서 한 printf 안에서 출발지, 목적지를 같이 부르면 둘 다 나중 값으로 덮인다.
     * 이 함정을 피하려고 출발지와 목적지를 따로 출력한다. */
    printf("[IP]       Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("           Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

    /* TCP 만 대상으로 한다. 필터로 tcp 만 잡지만 안전하게 한 번 더 확인한다. */
    if (ip->iph_protocol != IPPROTO_TCP) {
        printf("           (TCP 가 아니라 스킵)\n");
        return;
    }

    /* IP 헤더는 길이가 고정이 아니다(옵션이 붙을 수 있다).
     * iph_ihl 은 4바이트 단위 개수라서 4를 곱해야 실제 바이트 길이가 나온다.
     * 이 값을 알아야 TCP 헤더가 어디서 시작하는지 계산할 수 있다. */
    int ip_header_len = ip->iph_ihl * 4;

    /* 3. TCP 계층. IP 시작 위치에서 IP 헤더 길이만큼 건너뛴 곳이 TCP 헤더다.
     * sizeof(struct ipheader) 로 하면 옵션 붙은 IP 에서 어긋나므로 반드시 ip_header_len 을 쓴다. */
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

    printf("[TCP]      Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("           Dst Port: %d\n", ntohs(tcp->tcp_dport));

    /* TCP 헤더도 옵션 때문에 가변이다. 데이터 오프셋도 4바이트 단위라서 4를 곱한다. */
    int tcp_header_len = TH_OFF(tcp) * 4;

    /* 4. HTTP 메시지. 이더넷 + IP + TCP 헤더를 모두 지난 다음이 애플리케이션 데이터다. */
    int total_headers = ETHER_HDR_LEN + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_headers;
    const u_char *payload = packet + total_headers;

    if (payload_len > 0) {
        printf("[HTTP]     Message (%d bytes):\n", payload_len);
        print_payload(payload, payload_len);
    } else {
        printf("[HTTP]     (데이터 없음. 연결 제어용 패킷으로 보임)\n");
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *file = NULL;
    char *dev = NULL;
    int i;

    /* 인자 처리. -r 파일 은 저장된 pcap 을 읽고, -i 장치 는 그 장치에서 라이브로 잡는다. */
    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-r") == 0)
            file = argv[i + 1];
        else if (strcmp(argv[i], "-i") == 0)
            dev = argv[i + 1];
    }

    if (file) {
        handle = pcap_open_offline(file, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap 파일 열기 실패: %s\n", errbuf);
            return 1;
        }
        printf("저장된 파일에서 읽는 중: %s\n", file);
    } else {
        /* -i 로 장치를 안 주면 시스템의 첫 번째 장치를 자동으로 골라준다.
         * 예전 강의 코드의 pcap_lookupdev 는 요즘 라이브러리에서 폐기되어 pcap_findalldevs 를 쓴다. */
        if (dev == NULL) {
            pcap_if_t *alldevs;
            if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
                fprintf(stderr, "네트워크 장치를 찾지 못함: %s\n", errbuf);
                return 1;
            }
            dev = strdup(alldevs->name);
            pcap_freealldevs(alldevs);
        }
        /* 세 번째 인자 1 이 무차별 모드(promiscuous) 설정이다. */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "장치 열기 실패(%s): %s\n", dev, errbuf);
            return 1;
        }
        printf("라이브 캡처 중: %s (종료는 Ctrl-C)\n", dev);
    }

    /* 이 프로그램은 이더넷 프레임을 가정한다. 링크 타입이 다르면 헤더 오프셋이 달라진다. */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "경고: 이더넷 링크가 아님(datalink=%d). 결과가 어긋날 수 있음.\n",
                pcap_datalink(handle));
    }

    /* TCP 만 잡도록 BPF 필터를 건다. 와이어샤크 필터창에 tcp 치는 것과 같은 역할이다. */
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "필터 컴파일 실패: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터 적용 실패: %s\n", pcap_geterr(handle));
        return 1;
    }

    /* 패킷이 잡힐 때마다 got_packet 을 부른다. 두 번째 인자 -1 은 무한 반복이다. */
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
