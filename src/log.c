/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "log.h"
#include "thread.h" // for mutexes and atomics

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#define BUFFER_SIZE 4096
#define DUMP_IN_LINE 20

static const char *log_level_names[] = {"VERBOSE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

static const char *log_level_colors[] = {
    "\x1B[90m",        // grey
    "\x1B[96m",        // cyan
    "\x1B[39m",        // default foreground
    "\x1B[93m",        // yellow
    "\x1B[91m",        // red
    "\x1B[97m\x1B[41m" // white on red
};

static mutex_t log_mutex = MUTEX_INITIALIZER;
static volatile juice_log_cb_t log_cb = NULL;
static atomic(juice_log_level_t) log_level = ATOMIC_VAR_INIT(JUICE_LOG_LEVEL_WARN);

static bool use_color(void) {
#ifdef _WIN32
	return false;
#else
	return isatty(fileno(stdout)) != 0;
#endif
}

static int get_localtime(const time_t *t, struct tm *buf) {
#ifdef _WIN32
	// Windows does not have POSIX localtime_r...
	return localtime_s(buf, t) == 0 ? 0 : -1;
#else // POSIX
	return localtime_r(t, buf) != NULL ? 0 : -1;
#endif
}

JUICE_EXPORT void juice_set_log_level(juice_log_level_t level) { atomic_store(&log_level, level); }

JUICE_EXPORT void juice_set_log_handler(juice_log_cb_t cb) {
	mutex_lock(&log_mutex);
	log_cb = cb;
	mutex_unlock(&log_mutex);
}

bool juice_log_is_enabled(juice_log_level_t level) {
	return level != JUICE_LOG_LEVEL_NONE && level >= atomic_load(&log_level);
}

void juice_log_write(juice_log_level_t level, const char *file, int line, const char *fmt, ...) {
	if (!juice_log_is_enabled(level))
		return;

	mutex_lock(&log_mutex);

#if !RELEASE
	const char *filename = file + strlen(file);
	while (filename != file && *filename != '/' && *filename != '\\')
		--filename;
	if (filename != file)
		++filename;
#else
	(void)file;
	(void)line;
#endif

	if (log_cb) {
		char message[BUFFER_SIZE];
		int len = 0;
#if !RELEASE
		len = snprintf(message, BUFFER_SIZE, "%s:%d: ", filename, line);
		if (len < 0)
			goto __exit;
#endif
		if (len < BUFFER_SIZE) {
			va_list args;
			va_start(args, fmt);
			vsnprintf(message + len, BUFFER_SIZE - len, fmt, args);
			va_end(args);
		}

		log_cb(level, message);

	} else {
		time_t t = time(NULL);
		struct tm lt;
		char buffer[16];
		if (get_localtime(&t, &lt) != 0 || strftime(buffer, 16, "%H:%M:%S", &lt) == 0)
			buffer[0] = '\0';

		if (use_color())
			fprintf(stdout, "%s", log_level_colors[level]);

		fprintf(stdout, "%s %-7s ", buffer, log_level_names[level]);

#if !RELEASE
		fprintf(stdout, "%s:%d: ", filename, line);
#endif

		va_list args;
		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		va_end(args);

		if (use_color())
			fprintf(stdout, "%s", "\x1B[0m\x1B[0K");

		fprintf(stdout, "\n");
		fflush(stdout);
	}

__exit:
	mutex_unlock(&log_mutex);
}

void snprintf_hex(char *msg, size_t msg_len, const char *b, size_t len, const size_t in_line, const char *prefix)
{
    size_t i = 0;
    const char *end = b + len;
    if (prefix == NULL) {
        prefix = "";
    }

    while (i < len) {
        if (i % in_line ? 0 : 1) {
            snprintf(msg + i, msg_len, "\n%s", prefix);
        }
        snprintf(msg + i, msg_len, "%02X ", *(b+i));
		i++;
    }
    snprintf(msg + i, msg_len, "\n");
}

void fprintf_hex(FILE *file, const char *b, size_t len, const size_t in_line, const char *prefix, const char *suffix)
{
    size_t i = 0;

    if (prefix == NULL) {
        prefix = "";
    }

    while (i < len) {
        if (i % in_line ? 0 : 1) {
            fprintf(file, "\n%s", prefix);
        }
        fprintf(file, "%02X ", *(b+i));
		i++;
    }
    fprintf(file, "%s", suffix);
}

void juice_log_dump_hex(juice_log_level_t level, const char *file, int line, const char *buf, int length) {
	if (!juice_log_is_enabled(level))
		return;

	mutex_lock(&log_mutex);

#if !RELEASE
	const char *filename = file + strlen(file);
	while (filename != file && *filename != '/' && *filename != '\\')
		--filename;
	if (filename != file)
		++filename;
#else
	(void)file;
	(void)line;
#endif

	if (log_cb) {
		char message[BUFFER_SIZE];
		char prefix[128];
		int len = 0;
#if !RELEASE
		len = snprintf(prefix, 128, "%s:%d: ", filename, line);
		if (len < 0)
			goto __exit;
#endif
		snprintf_hex(message, BUFFER_SIZE, buf, length, DUMP_IN_LINE, prefix);

		log_cb(level, message);

	} else {
		char message[BUFFER_SIZE];
		char prefix[128];
		int len = 0;
		time_t t = time(NULL);
		struct tm lt;
		char buffer[16];
		if (get_localtime(&t, &lt) != 0 || strftime(buffer, 16, "%H:%M:%S", &lt) == 0)
			buffer[0] = '\0';

		if (use_color()) {
			snprintf(prefix, 128, "%s%s %-7s %s:%d: ", log_level_colors[level], buffer, log_level_names[level], filename, line);
		} else {
			snprintf(prefix, 128, "%s %-7s %s:%d: ", buffer, log_level_names[level], filename, line);
		}

#if !RELEASE
		fprintf_hex(stdout, buf, length, DUMP_IN_LINE, prefix, use_color() ? "\x1B[0m\x1B[0K\n" : "\n");
#endif
		fflush(stdout);
	}

__exit:
	mutex_unlock(&log_mutex);
}

#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
static void juice_log(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stdout, "Usage: %s [VERBOSE %d|DEBUG %d | INFO %d | WARN %d | ERROR %d | FATAL %d | NONE %d]",
		        argv[0], JUICE_LOG_LEVEL_VERBOSE, JUICE_LOG_LEVEL_DEBUG, JUICE_LOG_LEVEL_INFO,
		        JUICE_LOG_LEVEL_WARN, JUICE_LOG_LEVEL_ERROR, JUICE_LOG_LEVEL_FATAL, JUICE_LOG_LEVEL_NONE);
		fflush(stdout);
		return;
	}
	juice_set_log_level(atoi(argv[1]));
}

ALIOS_CLI_CMD_REGISTER(juice_log, juice_log, juice_log);
#endif