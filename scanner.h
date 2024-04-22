/**
 * @file scanner.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 19/04/2024
 * @brief Defines functions for scanning a TCP/UDP port
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <sys/socket.h>
#include "args.h"

/**
 * @brief Enumeration of possible results of a scan operation.
 */
enum result {
    Result_None,         ///< No result
    Result_Error,        ///< Error occurred during scanning
    Result_Done          ///< Scanning operation completed
};

struct scanner;

/**
 * @brief Function pointer type for setting up a scanner.
 *
 * This function is responsible for setting up the scanner with the provided arguments.
 *
 * @param scanner Pointer to the scanner structure.
 * @param args Pointer to the arguments structure containing setup parameters.
 * @return An integer representing the result of the setup operation. Zero indicates success, while a non-zero value indicates failure.
 */
typedef int (*ScannerSetupFunc)(struct scanner *scanner, const Args *args);

/**
 * @brief Function pointer type for creating a header for a packet.
 *
 * This function is responsible for creating the header for a packet to be sent during scanning.
 *
 * @param scanner Pointer to the scanner structure.
 * @param packet Pointer to the buffer where the packet header will be stored.
 * @param port The port number to include in the header.
 * @return The length of created header.
 */
typedef int (*MakeHeaderFunc)(struct scanner *scanner, uint8_t *packet, uint16_t port);

/**
 * @brief Function pointer type for handling a timeout during scanning.
 *
 * This function is called when a timeout occurs during scanning, allowing the scanner to react accordingly.
 *
 * @param scanner Pointer to the scanner structure.
 * @return An enumeration value representing the result of the timeout handling. Possible values are Result_None, Result_Error, and Result_Done.
 */
typedef enum result (*OnTimeoutFunc)(struct scanner *scanner);

/**
 * @brief Function pointer type for handling a received packet during scanning.
 *
 * This function is responsible for processing a received packet during scanning.
 *
 * @param scanner Pointer to the scanner structure.
 * @param packet Pointer to the buffer containing the received packet.
 * @param packet_len The length of the received packet.
 * @return An enumeration value representing the result of packet handling. Possible values are Result_None, Result_Error, and Result_Done.
 */
typedef enum result (*HandlePacketFunc)(struct scanner *scanner, const uint8_t *packet, size_t packet_len);

/**
 * @brief Struct representing a scanner for TCP/UDP port scanning.
 */
typedef struct scanner {
    int sendfd;                   ///< Socket for sending packets
    int recvfd;                   ///< Socket for receiving packets
    struct sockaddr *src_addr;    ///< Source address
    struct sockaddr *dst_addr;    ///< Destination address
    socklen_t src_addr_len;       ///< Length of the source address structure
    socklen_t dst_addr_len;       ///< Length of the destination address structure
    MakeHeaderFunc make_header;   ///< Function pointer to make header for packet
    OnTimeoutFunc on_timeout;     ///< Function pointer to handle timeout
    HandlePacketFunc handle_packet;///< Function pointer to handle received packet
    unsigned nof_retransmissions; ///< Number of retransmissions before timing out
    unsigned rate_limit;          ///< Rate limit between two port scans in milliseconds
    uint16_t current_port;        ///< Currently scanning port
} Scanner;

/**
 * @brief Create a new scanner instance.
 *
 * @param scanner Pointer to the scanner structure.
 * @param src_addr Pointer to the source address structure.
 * @param src_addr_len Length of the source address structure.
 * @param dst_addr Pointer to the destination address structure.
 * @param dst_addr_len Length of the destination address structure.
 */
void scanner_new(Scanner *scanner, struct sockaddr *src_addr, socklen_t src_addr_len, struct sockaddr *dst_addr, socklen_t dst_addr_len);

/**
 * @brief Close the sockets that owned by the scanner.
 *
 * @param scanner Pointer to the scanner structure.
 */
void scanner_close(Scanner *scanner);

/**
 * @brief Perform a port scan using the specified scanner.
 *
 * @param scanner Pointer to the scanner structure.
 * @param port The port to scan.
 * @param wait_time Time to wait for a response.
 */
void scanner_scan(Scanner *scanner, uint16_t port, unsigned wait_time);

#endif
