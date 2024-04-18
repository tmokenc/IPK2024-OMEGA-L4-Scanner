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
#include "time.h"

/// 8 KiB
#define PACKET_LEN (1 << 13)
#define SOURCE_PORT 49152 //1st ephemeral port
#define NOF_RETRANSMISSION 3

int make_header(uint8_t *packet, struct sockaddr *src_addr, struct sockaddr *dst_addr, uint16_t port) {
    struct udphdr *udp_header = (struct udphdr *)packet;
    udp_header->uh_sport = htons(SOURCE_PORT);
    udp_header->uh_dport = htons(port);
    udp_header->uh_ulen = htons(sizeof(struct udphdr)); // only the header len
    udp_header->uh_sum = 0; // 0 for now, will be check with pseudo header later
                              
    udp_header->uh_sum = checksum(
        packet, 
        sizeof(struct udphdr),
        src_addr,
        dst_addr,
        IPPROTO_UDP
    );

    return sizeof(struct udphdr);
}

void udp_scan(
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len,
    uint16_t port, int timeout
) {
    (void)src_len;
    // int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    // int recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sockfd = socket(src_addr->sa_family, SOCK_RAW, IPPROTO_UDP);
    int recvfd = socket(src_addr->sa_family, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0 || recvfd < 0) {
        perror("socket");
        return;
    }

    const int enable = 1;
    if (setsockopt(recvfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int))) {
        perror("setsockopt");
        close(sockfd);
        return;
    }

    uint8_t packet[PACKET_LEN];
    int packet_size = make_header(packet, src_addr, dst_addr, port);

    int res = sendto(sockfd, packet, packet_size, 0, dst_addr,  dst_len);

    if (res < 0) {
        perror("sendto");
        close(sockfd);
        close(recvfd);
        return;
    }

    // Catch and handle packet
    char recv_packet[PACKET_LEN];

    int flags = fcntl(recvfd, F_GETFL, 0);
    if (fcntl(recvfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl");
        close(sockfd);
        close(recvfd);
        return;
    }

    int nof_retransmission = 0;
    struct pollfd fd = {0};

    fd.fd = recvfd;
    fd.events = POLLIN;

    Timestamp start = timestamp_now();

    while (1) {
        int wait_time = timeout - timestamp_elapsed(start);
        if (wait_time < 0) wait_time = 0;

        int poll_result = poll(&fd, 1, wait_time);

        if (poll_result < 0) {
            perror("select");
            break;
        } else if (poll_result == 0) {
            if (nof_retransmission++ < NOF_RETRANSMISSION) {
                int res = sendto(sockfd, packet, packet_size, 0, dst_addr,  dst_len);
                start = timestamp_now();

                if (res < 0) {
                    perror("sendto");
                    break;
                }

                continue;
            }

            // Timeout reached
            printf("%d/udp open\n", port);
            break;
        } else {
            struct sockaddr recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            // Data is available to read from recvfd
            ssize_t bytes_received = recvfrom(recvfd, recv_packet, PACKET_LEN, 0, &recv_addr, &recv_addr_len);
            if (bytes_received < 0) {
                perror("recvfrom");
                break;
            }

            struct icmp *icmp_packet = (struct icmp *)bytes_received;

            if (src_addr->sa_family == AF_INET) {
                struct ip *ip_header = (struct ip *)recv_packet;
                size_t ip_header_length = ip_header->ip_hl * 4;
                icmp_packet = (struct icmp *)(recv_packet + ip_header_length);
            }

            if (icmp_packet->icmp_type != ICMP_UNREACH) {
                // Received ICMP packet, but not of type 3\n
                continue;
            }

            // Check if ICMP packet came from the expected address
            if (memcmp(&((struct sockaddr_in *)&recv_addr)->sin_addr, &((struct sockaddr_in *)dst_addr)->sin_addr, sizeof(struct in_addr)) != 0) {
                // Received ICMP packet from unexpected address
                continue;
            } 

            printf("%d/udp closed\n", port);
            break;
        }
    }

    close(sockfd);
    close(recvfd);
}
