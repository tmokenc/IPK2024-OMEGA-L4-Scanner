#include "udp.h"
#include "network.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
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

int udp_scanner_setup(Scanner *scanner, const Args *args) {
    scanner->make_header = udp_make_header;
    scanner->on_timeout = udp_on_timeout;
    scanner->handle_packet = udp_handle_packet;
    scanner->nof_retransmissions = args->nof_retransmissions;
    scanner->rate_limit = args->udp_ratelimit;

    int icmp_proto = scanner->dst_addr->sa_family == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP;

    scanner->sendfd = create_socket(args->interface, scanner->src_addr->sa_family, IPPROTO_UDP);
    scanner->recvfd = create_socket(args->interface, scanner->dst_addr->sa_family, icmp_proto);

    if (scanner->sendfd < 0 || scanner->recvfd < 0) {
        close(scanner->sendfd);
        close(scanner->recvfd);
        return -1;
    }

    return 0;
}

int udp_make_header(Scanner *scanner, uint8_t *packet, uint16_t port) {
    struct udphdr *udp_header = (struct udphdr *)packet;
    udp_header->uh_sport = htons(SOURCE_PORT);
    udp_header->uh_dport = htons(port);
    udp_header->uh_ulen = htons(sizeof(struct udphdr)); // only the header len
    udp_header->uh_sum = 0; // 0 for now, will be check with pseudo header later

    udp_header->uh_sum = checksum(
        packet,
        sizeof(struct udphdr),
        scanner->src_addr,
        scanner->dst_addr,
        IPPROTO_UDP
    );

    return sizeof(struct udphdr);
}

enum result udp_on_timeout(Scanner *scanner) {
    printf("%d/udp open\n", scanner->current_port);
    return Result_Done;
}

enum result udp_handle_packet(Scanner *scanner, const uint8_t *packet, size_t packet_len) {
    if (packet_len < sizeof(struct udphdr)) {
        return Result_None;
    }

    struct udphdr *udp_header = NULL;

    /// Checking the ICMP packet
    if (scanner->dst_addr->sa_family == AF_INET6) {
        struct icmp6_hdr *icmpv6_packet = (struct icmp6_hdr *)(packet);
        
        if (icmpv6_packet->icmp6_type != ICMP6_DST_UNREACH 
           || icmpv6_packet->icmp6_code != ICMP6_DST_UNREACH_NOPORT
        ) {
            // Received ICMP packet, but not the type we want
            return Result_None;
        }

        /// It has 4 unused bytes before the message body
        uint8_t *data = icmpv6_packet->icmp6_dataun.icmp6_un_data8 + 4;

        // struct ip6_hdr *ip_header = (struct ip6_hdr *)data;
        // UDP header is next to the IPv6 header
        udp_header = (struct udphdr *)(data + sizeof(struct ip6_hdr));
    } else {
        struct icmp *icmp_packet = (struct icmp *)packet;

        if (icmp_packet->icmp_type != ICMP_UNREACH || icmp_packet->icmp_code != ICMP_UNREACH_PORT) {
            // Received ICMP packet, but not the type we want
            return Result_None;
        }

        /// The last 8 bytes of the ICMP packet contains a fragment of the header we sent.
        int udp_header_offset = packet_len - 8;
        udp_header = (struct udphdr *)(packet + udp_header_offset);
    }

    if (ntohs(udp_header->uh_dport) != scanner->current_port) {
        // The ICMP packet is not from the port that we are scanning
        return Result_None;
    }

    printf("%d/udp closed\n", scanner->current_port);
    return Result_Done;
}
