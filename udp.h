/**
 * @file udp.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Define function for scanning UDP port
 */

#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <sys/socket.h>

void udp_scan(
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len,
    uint16_t port, int timeout
);

#endif

