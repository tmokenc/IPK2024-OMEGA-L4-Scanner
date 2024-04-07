/**
 * @file args.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Definitions and functions related to command-line arguments parsing.
 */

#ifndef ARGS_H
#define ARGS_H

#include <stdint.h>

/**
 * @struct Args
 * @brief Structure to hold parsed command-line arguments.
 */
typedef struct {
    char *interface;            /**< Network interface to scan through. */
    char *target_host;          /**< Target host (IPv4/IPv6 address or domain name). */
    unsigned wait_time_millis;  /**< Timeout in milliseconds for a single port scan. */
    uint16_t *udp_port;         /**< Array of UDP ports to scan. */
    uint16_t *tcp_port;         /**< Array of TCP ports to scan. */
    int udp_port_count;         /**< Number of UDP ports to scan. */
    int tcp_port_count;         /**< Number of TCP ports to scan. */
} Args;

/**
 * @brief Parse command-line arguments and populate Args structure.
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return Parsed command-line arguments in Args structure.
 */
Args args_parse(int argc, char **argv);

/**
 * @brief Free memory allocated for Args structure.
 * @param args Pointer to the Args structure.
 */
void args_free(Args *args);

#endif
