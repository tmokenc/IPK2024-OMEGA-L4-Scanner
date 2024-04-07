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

int print_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    
    // Get a list of available network interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Print the list of interfaces
    printf("Available network interfaces:\n");
    pcap_if_t *interface = interfaces;
    while (interface) {
        printf("- %s\n", interface->name);
        interface = interface->next;
    }

    // Free the memory allocated for the interface list
    pcap_freealldevs(interfaces);
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
