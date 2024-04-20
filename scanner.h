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

enum result {
    Result_None,
    Result_Error,
    Result_Retranmission,
    Result_Done,
};


struct scanner;

typedef int (*ScannerInitFunc)(struct scanner *scanner, const char *interface, struct sockaddr *src_addr, int src_addr_len, struct sockaddr *dst_addr, int dst_addr_len);
typedef int (*MakeHeaderFunc)(struct scanner *scanner, uint8_t *packet, uint16_t port);
typedef enum result (*OnTimeoutFunc)(struct scanner *scanner);
typedef enum result (*HandlePacketFunc)(struct scanner *scanner, uint8_t *packet, size_t packet_len);

typedef struct scanner {
    int sendfd;
    int recvfd;
    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    int src_addr_len;
    int dst_addr_len;
    MakeHeaderFunc make_header;
    OnTimeoutFunc on_timeout;
    HandlePacketFunc handle_packet;

    /// Number of retransmissions has done
    int nof_retransmissions;
    /// Currently scanning port
    uint16_t current_port;
} Scanner;

int scanner_init_tcp(Scanner *scanner, const char *interface, struct sockaddr *src_addr, int src_addr_len, struct sockaddr *dst_addr, int dst_addr_len);
int scanner_init_udp(Scanner *scanner, const char *interface, struct sockaddr *src_addr, int src_addr_len, struct sockaddr *dst_addr, int dst_addr_len);

void scanner_close(Scanner *scanner);

enum result scanner_scan(Scanner *scanner, uint16_t port, unsigned wait_time);

#endif
