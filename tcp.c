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
#include "time.h"
/// 8 KiB
#define PACKET_LEN 1 << 13
#define SOURCE_PORT 57489

int create_header(uint8_t *packet, struct sockaddr *src_addr, struct sockaddr *dst_addr, uint16_t port) {
    struct tcphdr *tcp_header = (struct tcphdr *)packet;

    tcp_header->th_sport = htons(SOURCE_PORT); // Source port
    tcp_header->th_dport = htons(port); // Destination port
    tcp_header->th_seq = htonl(0); // Sequence number
    tcp_header->th_ack = htonl(0); // Acknowledgment number
    tcp_header->th_off = 5; // Data offset (5 words = 20 bytes)
    tcp_header->th_flags = TH_SYN; // Flags (SYN)
    tcp_header->th_win = htons(65535); // Window size
    tcp_header->th_sum = 0; // Checksum (will be computed later)
    tcp_header->th_urp = 0; // Urgent pointer
    
    tcp_header->th_sum = checksum(
        packet,
        sizeof(struct tcphdr),
        src_addr,
        dst_addr,
        IPPROTO_TCP
    );

    return 0;
}

void tcp_scan(
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len,
    uint16_t port, int timeout
) {
    (void)src_len;

    // TODO
    //
    // Create socket
    int sockfd = socket(src_addr->sa_family, SOCK_RAW, IPPROTO_TCP);
    int recvfd = socket(src_addr->sa_family, SOCK_RAW, IPPROTO_TCP);

    if (sockfd < 0 || recvfd < 0) {
        perror("socket");
        return;
    }

    /// Set recvfd to work with raw header
    const int enable = 1;
    if (setsockopt(recvfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int))) {
        perror("setsockopt");
        close(sockfd);
        return;
    }


    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl");
        close(sockfd);
        return;
    }
    
    // Create Header
    uint8_t packet[PACKET_LEN];
    int packet_size = create_header(packet, src_addr, dst_addr, port);
    
    // Send packet
    int send_result = sendto(sockfd, packet, packet_size, 0, dst_addr, dst_len);

    if (send_result < 0) {
        close(sockfd);
        return;
    }

    // Receive packet
    
    struct pollfd fd = {0};

    fd.fd = recvfd;
    fd.events = POLLIN;

    int nof_retransmission = 0;
    Timestamp start = timestamp_now();
    char recv_packet[PACKET_LEN];

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
            if (nof_retransmission++ >= 1) {
                // --> timeout = filtered
                printf("%d/tcp filtered\n", port);
                break;
            }

            // Try to check again
            int send_result = sendto(sockfd, packet, packet_size, 0, dst_addr, dst_len);

            if (send_result < 0) {
                perror("sendto");
                break;
            }
        } else {
            struct sockaddr recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            // Data is available to read from recvfd
            ssize_t bytes_received = recvfrom(recvfd, recv_packet, PACKET_LEN, 0, &recv_addr, &recv_addr_len);

            if (bytes_received < 0) {
                perror("recvfrom");
                break;
            }

            if (memcmp(&((struct sockaddr_in *)&recv_addr)->sin_addr, &((struct sockaddr_in *)dst_addr)->sin_addr, sizeof(struct in_addr)) != 0) {
                // Receive packet from another address
                continue;
            } 

            /// Check TCP packet
            struct ip *ip_header = (struct ip *)recv_packet;
            size_t ip_header_length = ip_header->ip_hl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(recv_packet + ip_header_length);

            // Check TCP flags to determine port status
            // ->> RST       => closed
            // ->> SYN | ACK => open
            if (tcp_header->th_flags & TH_RST) {
                printf("%d/tcp closed\n", port);
            } else if (tcp_header->th_flags & TH_SYN && tcp_header->th_flags & TH_ACK) {
                printf("%d/tcp open\n", port);
            } else {
                // Other TCP flags scenario, consider port as filtered
                printf("%d/tcp filtered\n", port);
            }

            break;
        }
    }

    close(sockfd);
}
