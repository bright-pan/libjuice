/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_LOG_H
#define JUICE_LOG_H

#include "juice.h"

#include <stdarg.h>

bool juice_log_is_enabled(juice_log_level_t level);
void juice_log_write(juice_log_level_t level, const char *file, int line, const char *fmt, ...);
void juice_log_dump_hex(juice_log_level_t level, const char *file, int line, const void *buf, int length);

#define JLOG_VERBOSE(...) juice_log_write(JUICE_LOG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_DEBUG(...) juice_log_write(JUICE_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_INFO(...) juice_log_write(JUICE_LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_WARN(...) juice_log_write(JUICE_LOG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_ERROR(...) juice_log_write(JUICE_LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_FATAL(...) juice_log_write(JUICE_LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#define JLOG_VERBOSE_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_VERBOSE)
#define JLOG_DEBUG_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_DEBUG)
#define JLOG_INFO_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_INFO)
#define JLOG_WARN_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_WARN)
#define JLOG_ERROR_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_ERROR)
#define JLOG_FATAL_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_FATAL)

#define JLOG_VERBOSE_DUMP_HEX(...) juice_log_dump_hex(JUICE_LOG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_DEBUG_DUMP_HEX(...) juice_log_dump_hex(JUICE_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_INFO_DUMP_HEX(...) juice_log_dump_hex(JUICE_LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_WARN_DUMP_HEX(...) juice_log_dump_hex(JUICE_LOG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_ERROR_DUMP_HEX(...) juice_log_dump_hex(JUICE_LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_FATAL_DUMP_HEX(...) juice_log_dump_hex(JUICE_LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#if defined(CONFIG_LIBJUICE_USE_MBEDTLS) && defined(MBEDTLS_DEBUG_C)
void _ssl_debug(void *ctx, int level, const char *file, int line, const char *str);
#endif

#endif // JUICE_LOG_H
