/**
 * @file scanner.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 19/04/2024
 * @brief Implementation for `scanner.h`
 */

#include "scanner.h"
#include "time.h"
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include "network.h"

/// 2^13 = or 8 KiB is enough for all type of packets we need.
#define PACKET_LEN 1 << 13

/// Randomly chosen
uint16_t SOURCE_PORT = 57489;

void scanner_new(Scanner *scanner, struct sockaddr *src_addr, socklen_t src_addr_len, struct sockaddr *dst_addr, socklen_t dst_addr_len) {
    memset(scanner, 0, sizeof(Scanner));

    scanner->src_addr = src_addr;
    scanner->dst_addr = dst_addr;
    scanner->src_addr_len = src_addr_len;
    scanner->dst_addr_len = dst_addr_len;
    set_port(src_addr, SOURCE_PORT);
}

void scanner_close(Scanner *scanner) {
    close(scanner->sendfd);
    close(scanner->recvfd);
}

void rate_limit(Scanner *scanner) {
    static Timestamp LAST_SCAN_ON;

    if (LAST_SCAN_ON) {
        Timestamp elapsed = timestamp_elapsed(LAST_SCAN_ON);
        int wait_time = scanner->rate_limit - elapsed;

        if (wait_time > 0) {
            // sleep for n milliseconds
            // by Neuron
            // https://stackoverflow.com/a/1157217
            struct timespec ts;
            int res;

            ts.tv_sec = wait_time / 1000;
            ts.tv_nsec = (wait_time % 1000) * 1000000;

            do {
                res = nanosleep(&ts, &ts);
            } while (res && errno == EINTR);
        }

    }

    LAST_SCAN_ON = timestamp_now();
    
}

enum result scanner_scan(Scanner *scanner, uint16_t port, unsigned wait_time) {
    rate_limit(scanner);

    /// Set dst port to the scanning port
    /// Cannot set directly in the `dst_addr`, it gave me invalid argument
    scanner->current_port = port;

    /// Make header
    uint8_t packet[PACKET_LEN];
    int packet_size = scanner->make_header(scanner, packet, port);

    /// Send packet
    int res = sendto(scanner->sendfd, packet, packet_size, 0, scanner->dst_addr, scanner->dst_addr_len);

    if (res < 0) {
        perror("ERR sendto");
        return Result_Error;
    }

    /// Start receiving packet
    uint8_t recv_packet[PACKET_LEN];

    struct pollfd fd = {0};
    fd.fd = scanner->recvfd;
    fd.events = POLLIN;

    unsigned nof_retransmissions = 0;
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
            // Retranmission packet until it met the number of retranmissions.
            if (nof_retransmissions++ < scanner->nof_retransmissions) {
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

            result = scanner->on_timeout(scanner);
        } else {
            struct sockaddr_storage recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            int packet_len = recvfrom(scanner->recvfd, recv_packet, PACKET_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);

            // Checking packet
            int ip_header_length = 0;

            if (scanner->dst_addr->sa_family == AF_INET) {
                if (memcmp(&((struct sockaddr_in *)&recv_addr)->sin_addr, &((struct sockaddr_in *)scanner->dst_addr)->sin_addr, sizeof(struct in_addr)) != 0) {
                    // Received packet from unexpected address
                    continue;
                }

                struct ip *ip_header = (struct ip *)recv_packet;
                ip_header_length = ip_header->ip_hl * 4;
            } else {
                if (memcmp(&((struct sockaddr_in6 *)&recv_addr)->sin6_addr, &((struct sockaddr_in6 *)scanner->dst_addr)->sin6_addr, sizeof(struct in6_addr)) != 0) {
                    // Received packet from unexpected address
                    continue;
                }
            }

            uint8_t *packet = recv_packet + ip_header_length;
            uint8_t len = packet_len - ip_header_length;

            result = scanner->handle_packet(scanner, packet, len);
        }

        if (result == Result_Done) {
            break;
        }
    }

    return 0;
}
