/**
 * @file args.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 07/04/2024
 * @brief Implementation of the `args.h`
 */

#include "args.h"
#include <stdlib.h>

Args args_parse(int argc, char **argv) {
    Args result;

    // TODO

    return result;
}

void args_free(Args *args) {
    if (args->udp_port) {
        free(args->udp_port);
    }

    if (args->tcp_port) {
        free(args->tcp_port);
    }
}
