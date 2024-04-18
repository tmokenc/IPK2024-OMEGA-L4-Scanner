/**
 * @file network.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Declare functions related to networking.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <sys/socket.h>

typedef void (*ScanFunc)(
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len,
    uint16_t port, int timeout
);

/**
 * Pseudo header for UDP/TCP IPv4 for checksum
 */
struct pseudo_header_ipv4 {
    uint32_t src;
    uint32_t dst;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t len;
};

/**
 * Pseudo header for UDP/TCP IPv6 for checksum
 */
struct pseudo_header_ipv6 {
    uint64_t src[2];
    uint64_t dst[2];
    uint32_t len;
    uint8_t zeroes[3];
    uint8_t protocol;
};


int print_interfaces();
void print_address(struct sockaddr *);

int make_pseudo_header(uint8_t *buffer, struct sockaddr *src, struct sockaddr *dst, uint8_t protocol, uint32_t len);
uint16_t checksum(uint16_t *pseudo_header, int pseudo_header_len, uint16_t *buf, int buf_len);

int get_interface(
    const char *interface_name, 
    struct sockaddr *dst_addr, socklen_t dst_addr_len, 
    struct sockaddr_storage *src_addr, socklen_t *src_addr_len
);

#endif

