/**
 * @file udp.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Define function for scanning UDP port using `Scanner` interface.
 */

#ifndef UDP_H
#define UDP_H

#include "scanner.h"

int udp_make_header(Scanner *scanner, uint8_t *packet, uint16_t port);
enum result udp_on_timeout(Scanner *scanner);
enum result udp_handle_packet(Scanner *scanner, uint8_t *packet, size_t packet_len);

#endif

