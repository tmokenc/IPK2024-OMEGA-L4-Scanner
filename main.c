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
#include "scanner.h"

void for_each_port(
    Args args,
    Ports ports, 
    ScannerInitFunc scanner_init, 
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len
);

bool is_duplicated_addr(struct sockaddr *addr, struct addrinfo *address_info);
void print_address(struct sockaddr *addr);

const char *HELP = "UDP/TCP port scanner.\n"
"Usage: ./ipk-l4-scan <TARGET HOST> [OPTIONS]\n"
"Example: ./ipk-l4-scan -i eth0 -t 22,80,443 -u 1000-2000 localhost"
"Note:\n" 
"  - If no interface is provided, it will print list of interfaces.\n"
"  - In order for this program to work, it must be running with root priviledge.\n"
"  - In UDP there is a rate limit of 1000ms per scan to match with the ICMP packet generation rate limit by the kernel."
"\n"
"Option:\n"
"  -i, --interface <INTERFACE> (REQUIRED)  Choose the interface to scan through.\n"
"  -t, --pt <PORT>                         TCP ports to be scan.\n"
"  -u, --pu <PORT>                         UDP ports to be scan.\n"
"  -w, --wait <NUMBER>                     Wait time for response of each scan in milliseconds (default 5000).\n"
"  -r, --retransmissions <NUMBER>          Number of retransmissions in UDP (default 1).\n"
"  -l, --ratelimit <NUMBER>                Rate limit per port when scanning UDP in milliseconds (default 1000).\n"
"  -h, --help                              Print this message.\n"
"\n";

int main(int argc, char **argv) {
    Args args;

    if (!args_parse(&args, argc, argv)) {
        fprintf(stderr, "Cannot parse arguments\n");
        return 1;
    }

    if (args.is_help) {
        printf("%s", HELP);
        return 0;
    }

    if (!args.interface) {
        return print_interfaces();
    }

    /// Get address info of the hostname
    struct addrinfo *address_info;

    if (getaddrinfo(args.target_host, NULL, NULL, &address_info) != 0) {
        fprintf(stderr, "Cannot get the address info of %s\n", args.target_host);
        return 1;
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

        for_each_port(args, args.tcp_ports, scanner_init_tcp, (struct sockaddr *)&src_addr, src_len, dst_addr->ai_addr, dst_addr->ai_addrlen);
        for_each_port(args, args.udp_ports, scanner_init_udp, (struct sockaddr *)&src_addr, src_len, dst_addr->ai_addr, dst_addr->ai_addrlen);
        break;
    }

    freeaddrinfo(address_info);
    args_free(&args);

    return 0;
}

void for_each_port(
    Args args,
    Ports ports, 
    ScannerInitFunc scanner_init, 
    struct sockaddr *src_addr, socklen_t src_len,
    struct sockaddr *dst_addr, socklen_t dst_len
) {
    Scanner scanner = {0};
    bool initialized = false;
    switch (ports.type) {
        case PortType_Range:
            for (uint16_t port = ports.data.range.from; port <= ports.data.range.to; port++) {
                if (!initialized) {
                    int res = scanner_init(&scanner, args.interface, src_addr, src_len, dst_addr, dst_len);

                    if (res != 0) {
                        printf("Something went wrong\n");
                    }

                    initialized = true;
                }

                scanner_scan(&scanner, port, args.wait_time_millis);
            }
            break;

        case PortType_Specific:
            for (size_t i = 0; i < ports.data.specific.count; i++) {
                if (!initialized) {
                    int res = scanner_init(&scanner, args.interface, src_addr, src_len, dst_addr, dst_len);
                    if (res != 0) {
                        printf("Something went wrong\n");
                    }

                    initialized = true;
                }

                scanner_scan(&scanner, ports.data.specific.ports[i], args.wait_time_millis);
            }
            break;

        case PortType_None:
            break;
    }

    if (initialized) {
        scanner_close(&scanner);
    }
}
