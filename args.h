/**
 * @file args.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Definitions and functions related to command-line arguments parsing.
 */

#ifndef ARGS_H
#define ARGS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/**
 * @struct port_range
 * @brief Structure to represent a range of ports.
 */
struct port_range {
    uint16_t from; /**< Starting port number of the range. */
    uint16_t to;   /**< Ending port number of the range. */
};

/**
 * @struct port_specific
 * @brief Structure to represent specific ports.
 */
struct port_specific {
    uint16_t *ports; /**< Array of specific ports. */
    size_t count;    /**< Number of specific ports. */
};

/**
 * @enum ports_type
 * @brief Enumeration to represent different types of port specification.
 */
enum ports_type {
    PortType_None,     /**< Not specified. */
    PortType_Specific, /**< Specifies specific ports. */
    PortType_Range,    /**< Specifies a range of ports. */
};

/**
 * @struct Ports
 * @brief Structure to hold information about ports to scan.
 */
typedef struct {
    enum ports_type type; /**< Type of port specification. */
    union {
        struct port_specific specific; /**< Specific ports. */
        struct port_range range;       /**< Range of ports. */
    } data; /**< Union holding port information. */
} Ports;

/**
 * @struct Args
 * @brief Structure to hold parsed command-line arguments.
 */
typedef struct {
    char *interface;              /**< Network interface to scan through. */
    char *target_host;            /**< Target host (IPv4/IPv6 address or domain name). */
    unsigned wait_time_millis;    /**< Timeout in milliseconds for a single port scan. */
    Ports udp_ports;              /**< Ports to scan for UDP. */
    Ports tcp_ports;              /**< Ports to scan for TCP. */
    bool is_help;                 /**< If the argument require printing help message. */
    unsigned nof_retransmissions; /**< Number of retranmissions in UDP. */
    unsigned udp_ratelimit;       /**< Rate limit of UDP scanning per port. */
} Args;

/**
 * @brief Parse command-line arguments and populate Args structure.
 * @param result Pointer to the Args object to store the result.
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return Whether the parsing process was successful or not.
 */
bool args_parse(Args *result, int argc, char **argv);

/**
 * @brief Free memory allocated for Args structure.
 * @param args Pointer to the Args structure to be freed.
 */
void args_free(Args *args);

bool ports_is_empty(Ports *ports);

#endif
