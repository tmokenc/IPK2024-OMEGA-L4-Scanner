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

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

// Structure representing the UDP pseudo-header
struct pseudo_udp_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t udp_length;
};

int make_header(char *packet, struct sockaddr *src, socklen_t src_len, struct sockaddr *dst, socklen_t dst_len, uint16_t port) {
    // Construct IP header
    struct ip *ip_header = (struct ip *)packet;
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4; // IPv4
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr));
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0; // TBD later

    // Set source and destination addresses
    ip_header->ip_src.s_addr = inet_addr(inet_ntoa(((struct sockaddr_in *)src)->sin_addr));
    ip_header->ip_dst.s_addr = inet_addr(inet_ntoa(((struct sockaddr_in *)dst)->sin_addr));

    // (void)(src_len);
    // (void)(dst_len);
    // memcpy(&ip_header->ip_src, src, src_len);
    // memcpy(&ip_header->ip_dst, dst, dst_len);

    // Construct UDP header
    struct udp_header *udp_header = (struct udp_header *)(packet + sizeof(struct ip));
    udp_header->src_port = htons(SOURCE_PORT);
    udp_header->dst_port = htons(port);
    udp_header->len = htons(sizeof(struct udp_header));
    udp_header->checksum = 0; // Ignore for IPv4

    ip_header->ip_sum = checksum((uint16_t *)packet, sizeof(struct ip) + sizeof(struct udphdr));

    return sizeof(struct ip) + sizeof(struct udphdr);
}

void udp_scan(
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len,
    uint16_t port, int timeout
) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    int recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0 || recvfd < 0) {
        perror("socket");
        return;
    }

    const int enable = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int))) {
        perror("setsockopt");
        close(sockfd);
        return;
    }

    if (setsockopt(recvfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int))) {
        perror("setsockopt");
        close(sockfd);
        return;
    }

    char packet[PACKET_LEN];
    int packet_size = make_header(packet, src_addr, src_len, dst_addr, dst_len, port);
    
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

    struct pollfd fd = {0};

    fd.fd = recvfd;
    fd.events = POLLIN;

    Timestamp start = timestamp_now();

    while (1) {
        int wait_time = timeout - timestamp_elapsed(start);

        if (wait_time < 0) {
            wait_time = 0;
        }

        int poll_result = poll(&fd, 1, wait_time);

        if (poll_result < 0) {
            perror("select");
            break;
        } else if (poll_result == 0) {
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

            // Process the received ICMP packet
            struct ip *ip_header = (struct ip *)recv_packet;
            size_t ip_header_length = ip_header->ip_hl * 4;
            struct icmp *icmp_packet = (struct icmp *)(recv_packet + ip_header_length);

            if (icmp_packet->icmp_type != ICMP_UNREACH) {
                // Received ICMP packet, but not of type 3\n
                continue;
            }

            // Check if ICMP packet came from the expected address
            if (memcmp(&((struct sockaddr_in *)&recv_addr)->sin_addr, &((struct sockaddr_in *)dst_addr)->sin_addr, sizeof(struct in_addr)) != 0) {
                printf("Received ICMP packet from unexpected address\n");
                print_address(&recv_addr);
                printf("\n");
                continue;
            } 

            printf("%d/udp closed\n", port);
            break;
        }
    }

    close(sockfd);
    close(recvfd);
}
