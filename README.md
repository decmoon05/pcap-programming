# PCAP Programming - TCP 패킷 파서

libpcap(PCAP API)를 이용해서 TCP 패킷을 캡처하고, 이더넷/IP/TCP 헤더를 순서대로
파싱한 다음 그 뒤에 오는 HTTP 메시지까지 출력하는 프로그램이다.
화이트햇스쿨 네트워크 보안 과제(PCAP Programming)로 작성했다.

## 출력하는 정보

- 이더넷 헤더: 출발지 / 목적지 MAC 주소
- IP 헤더: 출발지 / 목적지 IP 주소
- TCP 헤더: 출발지 / 목적지 포트
- HTTP 메시지: 애플리케이션 계층 데이터 (평문 HTTP 일 때)

TCP 패킷만 대상으로 하고 UDP 는 무시한다. BPF 필터를 tcp 로 걸어서 처리한다.

## 파일 구성

- `pcap_parser.c` : 메인 소스
- `Makefile` : 빌드 스크립트
- `sample_http.pcap` : 테스트용 캡처 파일 (example.com 에 HTTP 요청한 것)

## 빌드

libpcap 개발 헤더가 필요하다.

```
sudo apt install libpcap-dev
make
```

## 실행

저장된 pcap 파일을 읽는 경우:

```
./pcap_parser -r sample_http.pcap
```

라이브로 잡는 경우 (무차별 모드라서 관리자 권한이 필요하고, eth0 은 본인 인터페이스로 바꾼다):

```
sudo ./pcap_parser -i eth0
```

인터페이스를 지정하지 않으면 시스템의 첫 번째 장치를 자동으로 고른다.

## 실행 예시

```
$ ./pcap_parser -r sample_http.pcap

[Packet #4]
[Ethernet] Dst MAC : b0:38:6c:49:17:a7
           Src MAC : 88:f4:da:74:d0:b5
[IP]       Src IP  : 192.168.0.2
           Dst IP  : 172.66.147.243
[TCP]      Src Port: 46537
           Dst Port: 80
[HTTP]     Message (75 bytes):
GET / HTTP/1.1
Host: example.com
User-Agent: curl/7.68.0
Accept: */*
```

## 개발 환경

Ubuntu 20.04 (WSL2), gcc 9.4, libpcap 1.9.1
