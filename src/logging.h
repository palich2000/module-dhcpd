#include <stdio.h>

/*
 * Logging macros
 */

#define log_info(str, ...)  LOG_INF(str, __VA_ARGS__)
#define log_error(str, ...) LOG_ERR(str, __VA_ARGS__)