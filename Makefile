CC = gcc
CFLAGS = -Wall
LDLIBS = -lpcap
TARGET = pcap_parser

all: $(TARGET)

$(TARGET): pcap_parser.c
	$(CC) $(CFLAGS) -o $(TARGET) pcap_parser.c $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
