/**
 * @file time.h
 * @author Le Duy Nguyen (xnguye27)
 * @date 25/03/2024
 * @brief Utility module. Defines functions related to time measurement.
 */

#ifndef TIME_H
#define TIME_H

/**
 * @brief Type representing a timestamp in milliseconds.
 */
typedef unsigned long long Timestamp;

/**
 * @brief Get the current timestamp in milliseconds.
 * @return The current timestamp in milliseconds.
 */
Timestamp timestamp_now();

/**
 * @brief Calculate the elapsed time in milliseconds since the specified timestamp.
 * @param timestamp The starting timestamp.
 * @return The elapsed time in milliseconds.
 */
int timestamp_elapsed(Timestamp timestamp);

#endif
