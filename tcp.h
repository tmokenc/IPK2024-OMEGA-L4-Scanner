/**
 * @file tcp.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Define function for scanning TCP port using `Scanner` interface.
 */

#ifndef TCP_H
#define TCP_H

#include "scanner.h"

int tcp_make_header(Scanner *scanner, uint8_t *packet, uint16_t port);
enum result tcp_on_timeout(Scanner *scanner);
enum result tcp_handle_packet(Scanner *scanner, uint8_t *packet, size_t packet_len);

#endif
