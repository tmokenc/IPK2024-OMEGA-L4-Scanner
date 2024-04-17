/**
 * @file main.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Starting point of the OMAGE L4 scanner project
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap.h>
#include "args.h"
#include "network.h"
#include "tcp.h"
#include "udp.h"

void for_each_port(
    Ports ports, 
    ScanFunc scanner, 
    unsigned timeout, 
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len
);

bool is_duplicated_addr(struct sockaddr *addr, struct addrinfo *address_info);
void print_address(struct sockaddr *addr);

int main(int argc, char **argv) {
    Args args;

    if (!args_parse(&args, argc, argv)) {
        fprintf(stderr, "Cannot parse arguments\n");
        return 1;
    }

    if (!args.interface) {
        return print_interfaces();
    }

    /// Get address info of the hostname
    struct addrinfo *address_info;

    if (getaddrinfo(args.target_host, NULL, NULL, &address_info) != 0) {
        fprintf(stderr, "Cannot get the address info of %s\n", args.target_host);
    }

    struct sockaddr_storage src_addr = {0};
    socklen_t src_len = sizeof(struct sockaddr_storage);

    /// Loop through all IP addresses
    for (struct addrinfo *dst_addr = address_info; dst_addr; dst_addr = dst_addr->ai_next) {
        memcpy(&src_addr, dst_addr->ai_addr, dst_addr->ai_addrlen);
        if (get_interface(args.interface, dst_addr->ai_addr, dst_addr->ai_addrlen, &src_addr, &src_len) != 0) {
            continue;
        }

        printf("Interesting ports on %s (", args.target_host);
        print_address(dst_addr->ai_addr);
        printf("):\nPORT STATE\n");

        for_each_port(args.tcp_ports, tcp_scan, args.wait_time_millis, (struct sockaddr *)&src_addr, src_len, dst_addr->ai_addr, dst_addr->ai_addrlen);
        for_each_port(args.udp_ports, udp_scan, args.wait_time_millis, (struct sockaddr *)&src_addr, src_len, dst_addr->ai_addr, dst_addr->ai_addrlen);
        break;
    }

    freeaddrinfo(address_info);
    args_free(&args);

    return 0;
}

void for_each_port(
    Ports ports, 
    ScanFunc scanner, 
    unsigned timeout, 
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len
) {
    switch (ports.type) {
        case PortType_Range:
            for (uint16_t port = ports.data.range.from; port <= ports.data.range.to; port++) {
                scanner(src_addr, src_len, dst_addr, dst_len, port, timeout);
            }
            break;

        case PortType_Specific:
            for (size_t i = 0; i < ports.data.specific.count; i++) {
                scanner(src_addr, src_len, dst_addr, dst_len, ports.data.specific.ports[i], timeout);
            }
            break;

        case PortType_None:
            break;
    }
}
