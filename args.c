/**
 * @file args.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Implementation of the `args.h`
 */

#include "args.h"
#include "network.h"
#include <stdlib.h>
#include <string.h>

bool string_match(const char *str, const char *str_short, const char *str_long) {
    return strcmp(str, str_short) == 0 || strcmp(str, str_long) == 0;
}

bool parse_range(const char *str, Ports *ports) {
    memset(ports, 0, sizeof(Ports));

    bool state_2 = false;

    for (int i = 0; str[i]; i++) {
        char ch = str[i];
        
        if (ch == '-' && !state_2) {
            state_2 = true;
            continue;
        }

        if (ch < '0' || ch > '9') {
            return false;
        }

        uint16_t *num = state_2 ? &ports->data.range.to : &ports->data.range.from;

        *num *= 10;
        *num += ch - '0';
    }

    if (ports->data.range.from >= ports->data.range.to) {
        return false;
    }
    
    ports->type = PortType_Range;
    return true;
}

bool parse_specific(const char *str, Ports *ports) {
    memset(ports, 0, sizeof(Ports));

    ports->data.specific.ports = (uint16_t *)malloc(sizeof(uint16_t));
    ports->data.specific.count = 1;

    if (!ports->data.specific.ports) {
        return false;
    }

    for (int i = 0; str[i]; i++) {
        char ch = str[i];
        if (ch == ',') {
            /// Check if the current number is duplicated or not
            uint16_t current_num = ports->data.specific.ports[ports->data.specific.count-1];
            for (size_t i = 0; i < ports->data.specific.count - 1; i++) {
                if (current_num == ports->data.specific.ports[i]) {
                    return false;
                }
            }

            uint16_t *tmp = realloc(ports->data.specific.ports, ++ports->data.specific.count * sizeof(uint16_t));

            if (!tmp) {
                return false;
            }

            tmp[ports->data.specific.count-1] = 0;
            ports->data.specific.ports = tmp;
            continue;
        }

        if (ch < '0' || ch > '9') {
            free(ports->data.specific.ports);
            return false;
        }

        ports->data.specific.ports[ports->data.specific.count - 1] *= 10;
        ports->data.specific.ports[ports->data.specific.count - 1] += ch - '0';
    }

    ports->type = PortType_Specific;
    return true;
}

bool parse_ports(const char *str, Ports *ports) {
    return parse_range(str, ports) || parse_specific(str, ports);
}

bool parse_number(const char *str, unsigned *output) {
    *output = 0;

    for (int i = 0; str[i]; i++) { 
        char ch = str[i];
        if (ch < '0' || ch > '9') {
            return false;
        }

        *output *= 10;
        *output += ch - '0';
    }

    return true;
}

bool args_parse(Args *result, int argc, char **argv) {
    memset(result, 0, sizeof(Args));

    result->wait_time_millis = 5000;
    result->udp_ratelimit = 1000;
    result->nof_retransmissions = 1;
    result->is_help = false;

    bool got_interface = false;
    bool got_udp_ports = false;
    bool got_tcp_ports = false;
    bool got_target_host = false;
    bool got_wait = false;
    bool got_retransmission = false;
    bool got_ratelimit = false;

    for (int i = 1; i < argc; i++) {
        if (string_match(argv[i], "-i", "--interface")) {
            if (got_interface) return false;

            i += 1;

            if (i >= argc) {
                // Only -i argument
                return true;
            }

            if (!is_valid_interface(argv[i])) {
                fprintf(stderr, "ERR %s is not a valid interface\n", argv[i]);
                return true;
            }

            result->interface = argv[i];
            got_interface = true;
            continue;
        }

        if (string_match(argv[i], "-t", "--pt")) {
            if (got_tcp_ports || !parse_ports(argv[++i], &result->tcp_ports)) {
                return false;
            }

            got_tcp_ports = true;
            continue;
        }

        if (string_match(argv[i], "-u", "--pu")) {
            if (got_udp_ports || !parse_ports(argv[++i], &result->udp_ports)) {
                return false;
            }

            got_udp_ports = true;
            continue;
        }

        if (string_match(argv[i], "-w", "--wait")) {
            if (got_wait || !parse_number(argv[++i], &result->wait_time_millis)) {
                return false;
            }

            got_wait = true;
            continue;
        }

        if (string_match(argv[i], "-r", "--retransmissions")) {
            if (got_retransmission || !parse_number(argv[++i], &result->nof_retransmissions)) {
                return false;
            }

            got_retransmission = true;
            continue;
        }

        if (string_match(argv[i], "-l", "--ratelimit")) {
            if (got_ratelimit || !parse_number(argv[++i], &result->udp_ratelimit)) {
                return false;
            }

            got_ratelimit = true;
            continue;
        }

        if (string_match(argv[i], "-h", "--help")) {
            result->is_help = true;
            return true;
        }

        if (got_target_host) return false;
        got_target_host = true;
        result->target_host = argv[i];
    }

    return true;
}

void args_free(Args *args) {
    if (args->udp_ports.type == PortType_Specific) {
        free(args->udp_ports.data.specific.ports);
    }

    if (args->tcp_ports.type == PortType_Specific) {
        free(args->tcp_ports.data.specific.ports);
    }
}

bool ports_is_empty(Ports *ports) {
    switch (ports->type) {
        case PortType_Range:
            return ports->data.range.to <= ports->data.range.from;

        case PortType_Specific:
            return ports->data.specific.count == 0;

        case PortType_None:
            return true;
    }

    return false;
}
