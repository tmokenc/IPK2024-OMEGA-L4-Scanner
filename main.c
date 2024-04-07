/**
 * @file main.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Starting point of the OMAGE L4 scanner project
 */

#include <stdio.h>
#include <pcap.h>
#include "args.h"

void tcp_scan(const char *target, uint16_t port, int timeout);
void udp_scan(const char *target, uint16_t port, int timeout);
int print_interfaces();

int main(int argc, char **argv) {
    Args args;

    if (!args_parse(&args, argc, argv)) {
        fprintf(stderr, "Cannot parse arguments\n");
        return 1;
    }

    if (!args.interface) {
        return print_interfaces();
    }

    printf("PORT STATES\n");

    /// Scanning TCP ports
    switch (args.tcp_ports.type) {
        case PortType_Range:
            for (uint16_t port = args.tcp_ports.data.range.from; port <= args.tcp_ports.data.range.to; port++) {
                tcp_scan(args.target_host, port, args.wait_time_millis);
            }
            break;
        case PortType_Specific:
            for (size_t i = 0; i < args.tcp_ports.data.specific.count; i++) {
                tcp_scan(args.target_host, args.tcp_ports.data.specific.ports[i], args.wait_time_millis);
            }

            break;
        case PortType_None:
            break;

    }

    /// Scanning UDP ports
    switch (args.udp_ports.type) {
        case PortType_Range:
            for (uint16_t port = args.udp_ports.data.range.from; port <= args.udp_ports.data.range.to; port++) {
                udp_scan(args.target_host, port, args.wait_time_millis);
            }
            break;
        case PortType_Specific:
            for (size_t i = 0; i < args.udp_ports.data.specific.count; i++) {
                udp_scan(args.target_host, args.udp_ports.data.specific.ports[i], args.wait_time_millis);
            }
            break;
        case PortType_None:
            break;

    }

    args_free(&args);

    return 0;
}

void tcp_scan(const char *target, uint16_t port, int timeout) {
    printf("TCP: %s:%d (%dms)\n", target, port, timeout);
    // TODO
}

void udp_scan(const char *target, uint16_t port, int timeout) {
    printf("UDP: %s:%d (%dms)\n", target, port, timeout);
    // TODO
}
