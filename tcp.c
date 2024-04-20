#include "tcp.h"
#include "network.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

extern uint16_t SOURCE_PORT;

int tcp_make_header(Scanner *scanner, uint8_t *packet, uint16_t port) {
    static uint16_t SEQ_NUMBER = 0;

    struct tcphdr *tcp_header = (struct tcphdr *)packet;

    tcp_header->th_sport = htons(SOURCE_PORT); // Source port
    tcp_header->th_dport = htons(port); // Destination port
    tcp_header->th_seq = htonl(SEQ_NUMBER++); // Sequence number
    tcp_header->th_ack = htonl(0); // Acknowledgment number
    tcp_header->th_off = 5; // Data offset (5 words = 20 bytes)
    tcp_header->th_flags = TH_SYN; // Flags (SYN)
    tcp_header->th_win = htons(0xFFFF); // Window size
    tcp_header->th_sum = 0; // Checksum (will be computed later)
    tcp_header->th_urp = 0; // Urgent pointer
    
    tcp_header->th_sum = checksum(
        packet,
        sizeof(struct tcphdr),
        scanner->src_addr,
        scanner->dst_addr,
        IPPROTO_TCP
    );

    return sizeof(struct tcphdr);
}

enum result tcp_on_timeout(Scanner *scanner) {
    if (scanner->nof_retransmissions >= 1) {
        // --> timeout = filtered
        printf("%d/tcp filtered\n", get_port(scanner->dst_addr));
        return Result_Done;
    }

    return Result_Retranmission;
}

enum result tcp_handle_packet(Scanner *scanner, uint8_t *packet, size_t packet_len) {
    if (packet_len < sizeof(struct tcphdr)) {
        return Result_None;
    }

    struct tcphdr *tcp_header = (struct tcphdr *)packet;
    uint16_t port = get_port(scanner->dst_addr);

    // Check TCP flags to determine port status
    if (tcp_header->th_flags & TH_RST) {
        // ->> RST       => closed
        printf("%d/tcp closed\n", port);
    } else if (tcp_header->th_flags & TH_SYN && tcp_header->th_flags & TH_ACK) {
        // ->> SYN | ACK => open
        printf("%d/tcp open\n", port);
    } else {
        // Other TCP flags scenario, consider port as filtered
        printf("%d/tcp filtered\n", port);
    }

    return Result_Done;
}
