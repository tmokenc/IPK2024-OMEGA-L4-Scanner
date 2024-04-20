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
#include <stdbool.h>

int print_interfaces();
bool is_valid_interface(const char *name);
void print_address(struct sockaddr *);

void set_port(struct sockaddr *addr, uint16_t port);
uint16_t get_port(struct sockaddr *addr);

uint16_t checksum(uint8_t *buf, int buf_len, struct sockaddr *src_addr, struct sockaddr *dst_addr, uint8_t protocol);

int get_interface(
    const char *interface_name, 
    struct sockaddr *dst_addr, socklen_t dst_addr_len, 
    struct sockaddr_storage *src_addr, socklen_t *src_addr_len
);

#endif

