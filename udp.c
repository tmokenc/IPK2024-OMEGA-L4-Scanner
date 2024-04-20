#include "udp.h"
#include "network.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>

#define NOF_RETRANSMISSION 1

extern uint16_t SOURCE_PORT;

int udp_make_header(Scanner *scanner, uint8_t *packet, uint16_t port) {
    struct udphdr *udp_header = (struct udphdr *)packet;
    udp_header->uh_sport = htons(SOURCE_PORT);
    udp_header->uh_dport = htons(port);
    udp_header->uh_ulen = htons(sizeof(struct udphdr)); // only the header len
    udp_header->uh_sum = 0; // 0 for now, will be check with pseudo header later

    udp_header->uh_sum = checksum(
        packet,
        sizeof(struct udphdr),
        (struct sockaddr *)&scanner->src_addr,
        (struct sockaddr *)&scanner->dst_addr,
        IPPROTO_UDP
    );

    return sizeof(struct udphdr);
}

enum result udp_on_timeout(Scanner *scanner) {
    if (scanner->nof_retransmissions < NOF_RETRANSMISSION) {
        return Result_Retranmission;
    }

    printf("%d/udp open\n", get_port((struct sockaddr *)&scanner->dst_addr));
    return Result_Done;
}

enum result udp_handle_packet(Scanner *scanner, uint8_t *packet, size_t packet_len) {
    if (packet_len < sizeof(struct udphdr)) {
        return Result_None;
    }

    struct icmp *icmp_packet = (struct icmp *)packet;

    if (icmp_packet->icmp_type != ICMP_UNREACH) {
        // Received ICMP packet, but not of type 3
        return Result_None;
    }

    printf("%d/udp closed\n", get_port((struct sockaddr *)&scanner->dst_addr));
    return Result_Done;
}
