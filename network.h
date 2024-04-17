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

typedef struct {
    struct sockaddr *ipv4;
    struct sockaddr *ipv6;
} Interfaces;

int print_interfaces();
void print_address(struct sockaddr *);

uint16_t checksum(uint16_t *buf, int nwords);

int get_interface(
    const char *interface_name, 
    struct sockaddr *dst_addr, socklen_t dst_addr_len, 
    struct sockaddr_storage *src_addr, socklen_t *src_addr_len
);

#endif

