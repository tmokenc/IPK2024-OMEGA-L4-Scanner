#include "tcp.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/// 8 KiB
#define BUF_SIZE 1 << 13

struct pseudo_tcp_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero_padding;
    uint8_t protocol;
    uint16_t len;
};

// struct pseudo_tcp_ipv6_header {
//     struct in6_addr src;
//     struct in6_addr dst;
//     uint32_t len;
//     uint16_t zero_padding;
//     uint16_t zero_padding2;
//     uint8_t protocol;
// };

int create_header() {
    // TODO
    return 0;
}

void tcp_scan(
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len,
    uint16_t port, int timeout
) {
    (void)src_addr;
    (void)src_len;
    (void)dst_addr;
    (void)dst_len;
    (void)port;
    (void)timeout;

    // TODO
    //
    // Create socket
    /// IPv6 later
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (sockfd < 1) {
        perror("socket");
        close(sockfd);
        return;
    }

    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl");
        close(sockfd);
        return;
    }
    //
    // Create Header
    char header[BUF_SIZE];
    int header_size = create_header();
    //
    //
    // Send packet
    int send_result = send(sockfd, header, header_size, 0);

    if (send_result < 0) {
        close(sockfd);
        return;
    }

    // Receive packet
    
    struct pollfd fd = {0};

    fd.fd = sockfd;
    fd.events = POLLIN;

    while (1) {
        int poll_result = poll(&fd, 1, timeout);
    }
    //
    // --> timeout = filtered
    //
    // ->> RST | ACK => closed
    //
    // ->>> SYN | ACK => open
}
