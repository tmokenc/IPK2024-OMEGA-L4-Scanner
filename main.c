/**
 * @file main.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Starting point of the OMAGE L4 scanner project
 */

#include <stdio.h>
#include "args.h"

enum result {
    Result_Open,
    Result_Closed,
    Result_Filtered,
};

enum result tcp_scan(const char *target, int ports, int timeout);
enum result udp_scan(const char *target, int ports, int timeout);
void print_interfaces();

int main(int argc, char **argv) {
    Args args = args_parse(argc, argv);

    if (!args.interface) {
        print_interfaces();
        return 0;
    }

    printf("PORT STATES\n");

    for (int i = 0; i < args.tcp_port_count; i++) {
        enum result result = tcp_scan(args.target_host, args.tcp_port[i], args.wait_time_millis);
        // TODO
    }

    for (int i = 0; i < args.udp_port_count; i++) {
        enum result result = udp_scan(args.target_host, args.tcp_port[i], args.wait_time_millis);
        // TODO
    }

    args_free(&args);

    return 0;
}
