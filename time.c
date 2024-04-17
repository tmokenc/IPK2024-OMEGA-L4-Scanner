/**
 * @file time.c
 * @author Le Duy Nguyen (xnguye27)
 * @date 25/03/2024
 * @brief Implementation for time.h
 */

#include "time.h"
#include <sys/time.h>
#include <stdlib.h>

Timestamp timestamp_now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (Timestamp)(tv.tv_sec) * 1000 + (Timestamp)(tv.tv_usec) / 1000;
}

int timestamp_elapsed(Timestamp timestamp) {
    return timestamp_now() - timestamp;
}
