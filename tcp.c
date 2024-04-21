#include "tcp.h"
#include "network.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "tcp.h"

extern uint16_t SOURCE_PORT;

int tcp_scanner_setup(Scanner *scanner, const Args *args) {
    scanner->make_header = tcp_make_header;
    scanner->on_timeout = tcp_on_timeout;
    scanner->handle_packet = tcp_handle_packet;
    scanner->nof_retransmissions = 1;

    scanner->sendfd = create_socket(args->interface, scanner->src_addr->sa_family, IPPROTO_TCP);
    scanner->recvfd = create_socket(args->interface, scanner->dst_addr->sa_family, IPPROTO_TCP);

    if (scanner->sendfd < 0 || scanner->recvfd < 0) {
        close(scanner->sendfd);
        close(scanner->recvfd);
        return -1;
    }
    return 0;
}

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
    // --> timeout = filtered
    printf("%d/tcp filtered\n", scanner->current_port);
    return Result_Done;
}

enum result tcp_handle_packet(Scanner *scanner, const uint8_t *packet, size_t packet_len) {
    if (packet_len < sizeof(struct tcphdr)) {
        return Result_None;
    }

    struct tcphdr *tcp_header = (struct tcphdr *)packet;

    uint16_t port = ntohs(tcp_header->th_sport);

    if (port != scanner->current_port) {
        /// Not the port we want
        return Result_None;
    }

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
