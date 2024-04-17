/**
 * @file tcp.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Define function for scanning TCP port
 */

#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <sys/socket.h>

void tcp_scan(
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len,
    uint16_t port, int timeout
);

#endif
