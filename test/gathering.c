/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "test_config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif


static juice_agent_t *agent = NULL;
static bool success = false;
static bool done = false;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_gathering_done(juice_agent_t *agent, void *user_ptr);

int test_gathering() {

	// Turn server config
	juice_turn_server_t turn_server;
	memset(&turn_server, 0, sizeof(turn_server));
	turn_server.host = TURN_SERVER_HOST;
	turn_server.port = TURN_SERVER_PORT;
	turn_server.username = TURN_SERVER_USERNAME;
	turn_server.password = TURN_SERVER_PASSWORD;

	// Create agent
	juice_config_t config;
	memset(&config, 0, sizeof(config));

	config.concurrency_mode = JUICE_CONCURRENCY_MODE_THREAD;
	// STUN server example
	// config.stun_server_host = "test.funlink.cloud";
	// config.stun_server_port = 3478;

	config.bind_address = "192.168.4.2";

	// TURN server example (use your own server in production)
	config.turn_servers = &turn_server;
	config.turn_servers_count = 1;

	config.cb_state_changed = on_state_changed;
	config.cb_candidate = on_candidate;
	config.cb_gathering_done = on_gathering_done;
	config.user_ptr = NULL;

	agent = juice_create(&config);

	// Generate local description
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description:\n%s\n", sdp);

	// Gather candidates
	juice_gather_candidates(agent);

	// Wait until gathering done
	int secs = 10;
	while (secs-- && !done && !success)
		sleep(1);

	// Destroy
	juice_destroy(agent);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}

	// Reset
	agent = NULL;
	success = false;
	done = false;
}

// On state changed
static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State: %s\n", juice_state_to_string(state));
}

// On local candidate gathered
static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate: %s\n", sdp);

	// Success if a valid srflx candidate is emitted
	if (strstr(sdp, " typ srflx raddr 0.0.0.0 rport 0"))
		success = true;
}

// On local candidates gathering done
static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done\n");

	done = true;
}
