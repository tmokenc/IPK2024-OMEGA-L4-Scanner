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

/**
 * @brief Create a non-blocking raw socket bound to a specific interface.
 *
 * @param interface The name of the network interface to bind the socket to.
 * @param family The address family for the socket (e.g., AF_INET for IPv4, AF_INET6 for IPv6).
 * @param protocol The transport protocol for the socket (e.g., IPPROTO_TCP for TCP, IPPROTO_UDP for UDP).
 * @return The file descriptor of the created socket, or -1 on error.
 */
int create_socket(const char *interface, int family, int protocol);

/**
 * @brief Print a list of available network interfaces.
 */
int print_interfaces();

/**
 * @brief Check if a given interface name is valid.
 *
 * @param name The name of the network interface to check.
 * @return true if the interface name is valid, false otherwise.
 */
bool is_valid_interface(const char *name);

/**
 * @brief Print the address stored in a sockaddr structure.
 *
 * @param addr Pointer to the sockaddr structure containing the address to print.
 */
void print_address(struct sockaddr *);

/**
 * @brief Set the port in a sockaddr structure.
 *
 * @param addr Pointer to the sockaddr structure whose port is to be set.
 * @param port The port number to set.
 */
void set_port(struct sockaddr *addr, uint16_t port);

/**
 * @brief Get the port from a sockaddr structure.
 *
 * @param addr Pointer to the sockaddr structure from which to retrieve the port.
 * @return The port number stored in the sockaddr structure.
 */
uint16_t get_port(struct sockaddr *addr);

/**
 * @brief Calculate the checksum for a UDP/TCP packet.
 *
 * @param buf Pointer to the buffer containing the packet data.
 * @param buf_len The length of the packet data.
 * @param src_addr Pointer to the source address structure.
 * @param dst_addr Pointer to the destination address structure.
 * @param protocol The transport protocol for the packet (e.g., IPPROTO_TCP for TCP, IPPROTO_UDP for UDP).
 * @return The calculated checksum value.
 */
uint16_t checksum(uint8_t *buf, int buf_len, struct sockaddr *src_addr, struct sockaddr *dst_addr, uint8_t protocol);

/**
 * @brief Get the source address information for a given interface and destination address.
 *
 * @param interface_name The name of the network interface.
 * @param dst_addr Pointer to the destination address structure.
 * @param dst_addr_len The length of the destination address structure.
 * @param src_addr Pointer to the source address structure (output parameter).
 * @param src_addr_len Pointer to the length of the source address structure (output parameter).
 * @return 0 if successful, -1 on error.
 */
int get_src_addr(
    const char *interface_name, 
    struct sockaddr *dst_addr, socklen_t dst_addr_len, 
    struct sockaddr_storage *src_addr, socklen_t *src_addr_len
);

#endif

