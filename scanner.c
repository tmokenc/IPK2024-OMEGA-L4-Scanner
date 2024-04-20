/**
 * @file scanner.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 19/04/2024
 * @brief Implementation for `scanner.h`
 */

#include "scanner.h"
#include "network.h"
#include "tcp.h"
#include "udp.h"
#include "time.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>

/// 2^13 = or 8 KiB is enough for all type of packets we need.
#define PACKET_LEN 1 << 13

/// Randomly chosen
uint16_t SOURCE_PORT = 57489;

int create_socket(Scanner *scanner, const char *interface, int send_type, int recv_type) {
    scanner->sendfd = socket(scanner->src_addr->sa_family, SOCK_RAW, send_type);
    scanner->recvfd = socket(scanner->src_addr->sa_family, SOCK_RAW, recv_type);

    if (scanner->sendfd < 0 || scanner->recvfd < 0) {
        close(scanner->sendfd);
        close(scanner->recvfd);
        perror("ERR create socket");
        return -1;
    }

    const int enable = 1;
    if (setsockopt(scanner->recvfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int))) {
        perror("ERR setsockopt");
        close(scanner->sendfd);
        close(scanner->recvfd);
        return -1;
    }

    /// Set receiving socket non-blocking for using with poll.
    int flags = fcntl(scanner->recvfd, F_GETFL, 0);
    if (fcntl(scanner->recvfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("ERR set non blocking fcntl");
        close(scanner->sendfd);
        close(scanner->recvfd);
        return -1;
    }

    int send_bind = setsockopt(scanner->sendfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));
    int recv_bind = setsockopt(scanner->recvfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));

    if (send_bind < 0 || recv_bind < 0) {
        perror("ERR bind interface setsockopt");
        close(scanner->sendfd);
        close(scanner->recvfd);
        return -1;
    }
    return 0;
}

int scanner_init_tcp(Scanner *scanner, const char *interface, struct sockaddr *src_addr, int src_addr_len, struct sockaddr *dst_addr, int dst_addr_len) {
    set_port(src_addr, SOURCE_PORT);
    scanner->src_addr = src_addr;
    scanner->dst_addr = dst_addr;
    scanner->src_addr_len = src_addr_len;
    scanner->dst_addr_len = dst_addr_len;
    scanner->make_header = tcp_make_header;
    scanner->on_timeout = tcp_on_timeout;
    scanner->handle_packet = tcp_handle_packet;

    if (create_socket(scanner, interface, IPPROTO_TCP, IPPROTO_TCP) != 0) {
        return -1;
    }

    return 0;
}

int scanner_init_udp(Scanner *scanner, const char *interface, struct sockaddr *src_addr, int src_addr_len, struct sockaddr *dst_addr, int dst_addr_len) {
    set_port(src_addr, SOURCE_PORT);
    scanner->src_addr = src_addr;
    scanner->dst_addr = dst_addr;
    scanner->src_addr_len = src_addr_len;
    scanner->dst_addr_len = dst_addr_len;
    scanner->make_header = udp_make_header;
    scanner->on_timeout = udp_on_timeout;
    scanner->handle_packet = udp_handle_packet;

    if (create_socket(scanner, interface, IPPROTO_UDP, IPPROTO_ICMP) != 0) {
        return -1;
    }

    return 0;
}

void scanner_close(Scanner *scanner) {
    close(scanner->sendfd);
    close(scanner->recvfd);
}

enum result scanner_scan(Scanner *scanner, uint16_t port, unsigned wait_time) {
    set_port(scanner->dst_addr, port);

    uint8_t packet[PACKET_LEN];
    int packet_size = scanner->make_header(scanner, packet, port);

    int res = sendto(scanner->sendfd, packet, packet_size, 0, scanner->dst_addr, scanner->dst_addr_len);

    if (res < 0) {
        perror("ERR sendto");
        return Result_Error;
    }

    uint8_t recv_packet[PACKET_LEN];

    struct pollfd fd = {0};
    fd.fd = scanner->recvfd;
    fd.events = POLLIN;

    scanner->nof_retransmissions = 0;
    Timestamp start = timestamp_now();
    enum result result = Result_None;

    /// Keep polling until we get the result
    while (1) {
        int timeout = wait_time - timestamp_elapsed(start);
        if (timeout < 0) timeout = 0;

        int poll_result = poll(&fd, 1, timeout);

        if (poll_result < 0) {
            // Got an error or a signal
            break;
        }

        if (poll_result == 0) {
            result = scanner->on_timeout(scanner);
        } else {
            struct sockaddr recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            int packet_len = recvfrom(scanner->recvfd, recv_packet, PACKET_LEN, 0, &recv_addr, &recv_addr_len);

            if (memcmp(&((struct sockaddr_in *)&recv_addr)->sin_addr, &((struct sockaddr_in *)scanner->dst_addr)->sin_addr, sizeof(struct in_addr)) != 0) {
                // Received packet from unexpected address
                continue;
            } 

            int ip_header_length = 0;

            if (scanner->src_addr->sa_family == AF_INET) {
                struct ip *ip_header = (struct ip *)recv_packet;
                ip_header_length = ip_header->ip_hl * 4;
            }

            uint8_t *packet = recv_packet + ip_header_length;
            uint8_t len = packet_len - ip_header_length;

            result = scanner->handle_packet(scanner, packet, len);
        }

        if (result == Result_Done) {
            break;
        }

        if (result == Result_Retranmission) {
            int res = sendto(scanner->sendfd, packet, packet_size, 0, scanner->dst_addr, scanner->dst_addr_len);

            if (res < 0) {
                perror("ERR retranmission sendto");
                return Result_Error;
            }

            start = timestamp_now();
            result = Result_None;
            scanner->nof_retransmissions += 1;

            continue;
        }
    }

    return 0;
}
