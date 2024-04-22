/**
 * @file tcp.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Define function for scanning TCP port using `Scanner` interface.
 */

#ifndef TCP_H
#define TCP_H

#include "scanner.h"
#include "args.h"

/**
 * @brief Setup function for TCP scanner.
 * @param scanner Pointer to the scanner structure.
 * @param args Pointer to the arguments structure containing setup parameters.
 * @return Result of the setup operation. Zero indicates success, while a non-zero value indicates failure.
 */
int tcp_scanner_setup(Scanner *scanner, const Args *args);

/**
 * @brief Function for creating a TCP packet header.
 * @param scanner Pointer to the scanner structure.
 * @param packet Pointer to the buffer where the TCP packet header will be stored.
 * @param port The port number to include in the header.
 * @return The length of created header
 */
int tcp_make_header(Scanner *scanner, uint8_t *packet, uint16_t port);

/**
 * @brief Function for handling a timeout during TCP scanning.
 * @param scanner Pointer to the scanner structure.
 * @return An enumeration value representing the result of the timeout handling.
 */
enum result tcp_on_timeout(Scanner *scanner);

/**
 * @brief Function for handling a received TCP packet during scanning.
 * @param scanner Pointer to the scanner structure.
 * @param packet Pointer to the buffer containing the received TCP packet.
 * @param packet_len The length of the received TCP packet.
 * @return An enumeration value representing the result of packet handling.
 */
enum result tcp_handle_packet(Scanner *scanner, const uint8_t *packet, size_t packet_len);

#endif
