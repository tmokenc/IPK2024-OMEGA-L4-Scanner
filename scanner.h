/**
 * @file scanner.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 19/04/2024
 * @brief Defines functions for scanning a TCP/UDP port
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <sys/socket.h>
#include "args.h"

enum result {
    Result_None,
    Result_Error,
    Result_Retranmission,
    Result_Done,
};

struct scanner;

typedef int (*ScannerSetupFunc)(struct scanner *scanner, const Args *args);

typedef int (*MakeHeaderFunc)(struct scanner *scanner, uint8_t *packet, uint16_t port);
typedef enum result (*OnTimeoutFunc)(struct scanner *scanner);
typedef enum result (*HandlePacketFunc)(struct scanner *scanner, const uint8_t *packet, size_t packet_len);

typedef struct scanner {
    int sendfd;
    int recvfd;
    struct sockaddr *src_addr;
    struct sockaddr *dst_addr;
    socklen_t src_addr_len;
    socklen_t dst_addr_len;
    MakeHeaderFunc make_header;
    OnTimeoutFunc on_timeout;
    HandlePacketFunc handle_packet;

    /// Number of retransmissions need to be done before timing out
    unsigned nof_retransmissions;
    /// Rate limit between 2 port scans in milliseconds
    unsigned rate_limit;
    /// Currently scanning port
    uint16_t current_port;
} Scanner;

void scanner_new(Scanner *scanner, struct sockaddr *src_addr, socklen_t src_addr_len, struct sockaddr *dst_addr, socklen_t dst_addr_len);
void scanner_close(Scanner *scanner);

void scanner_scan(Scanner *scanner, uint16_t port, unsigned wait_time);

#endif
