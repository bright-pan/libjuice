#include "test_config.h"
#include "peer_connection.h"
#include "udp.h"
#include "log.h"
#include <cJSON.h>

#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
#include <aos/kernel.h>


extern void mqtt_offer_publish(char *sdp_content);
extern void mqtt_answer_publish(char *sdp_content);

char buffer[BUFFER_SIZE];

peer_connection_t peer_connection_server, peer_connection_client;
peer_options_t server_options, client_options;

static void on_state_change(peer_connection_state_t state, void *data) {

  JLOG_INFO("state is changed: %d\n", state);
}

static void pc_client(int argc, char **argv) {

    if (argc < 2) {
        JLOG_ERROR("\nUsage: %s create|start\nUsage: %s remote\nUsage: %s get local|remote", argv[0], argv[0], argv[0]);
        return;
    }
    peer_connection_t *pc = &peer_connection_client;
    peer_options_t *po = &client_options;
    if (strstr(argv[1], "create")) {
        peer_options_set_default(po, 57000, 58000);
        peer_connection_configure(pc, "peer_client", DTLS_SRTP_ROLE_CLIENT, po);
        peer_connection_set_cb_state_change(pc, on_state_change);
        peer_connection_init(pc);
    } else if (strstr(argv[1], "start")) {
            peer_connection_start(pc);
    } else if (strstr(argv[1], "remote")) {
        if (argc == 2) {
            juice_set_remote_description(pc->juice_agent, peer_connection_server.local_sdp.content);
        } else {
            JLOG_ERROR("Usage: %s remote", argv[0]);
        }
   } else if (strstr(argv[1], "push")) {
        if (strstr(argv[2], "offer")) {
            mqtt_offer_publish(pc->local_sdp.content);
        } else if (strstr(argv[2], "answer")) {
            mqtt_answer_publish(pc->local_sdp.content);
        } else {
            JLOG_ERROR("Usage: %s push offer|answer\n", argv[0]);
        }
   } else if (strstr(argv[1], "get")) {
        if (strstr(argv[2], "local")) {
            // juice_get_local_description(pc->juice_agent, pc->local_sdp.content, JUICE_MAX_SDP_STRING_LEN);
            JLOG_INFO("client local description:\n%s\n", pc->local_sdp.content);
        } else if (strstr(argv[2], "remote")) {
            juice_get_remote_description(pc->juice_agent, pc->remote_sdp.content, JUICE_MAX_SDP_STRING_LEN);
            JLOG_INFO("client remote description:\n%s\n", pc->remote_sdp.content);
        } else {
            JLOG_ERROR("Usage: %s get local|remote\n", argv[0]);
        }
    } else if (strstr(argv[1], "pair")) {
        if (argc == 2) {
            if (agent_get_selected_candidate_pair(pc->juice_agent, &pc->local_cand, &pc->remote_cand) == 0) {
                JLOG_INFO("%s local address:", pc->name);
                JLOG_ADDR_RECORD(&pc->local_cand.resolved);
                JLOG_INFO("%s remote address:", pc->name);
                JLOG_ADDR_RECORD(&pc->remote_cand.resolved);
            } else {
                JLOG_ERROR("no selected candidate pair\n", argv[0]);
            }
        } else {
            JLOG_ERROR("Usage: %s pair\n", argv[0]);
        }
    } else if (strstr(argv[1], "state")) {
        if (argc == 3) {
            STATE_CHANGED(pc, atoi(argv[2]));
        } else {
            JLOG_ERROR("Usage: %s state xxx\n", argv[0]);
        }
   } else if (strstr(argv[1], "state")) {
        if (argc == 3) {
            STATE_CHANGED(pc, atoi(argv[2]));
        } else {
            JLOG_ERROR("Usage: %s state xxx\n", argv[0]);
        }
    } else if (strstr(argv[1], "handshake")) {
        if (argc == 2) {
            JLOG_INFO("%s start handshake:", pc->name);
            JLOG_ADDR_RECORD(&pc->remote_cand.resolved);
            STATE_CHANGED(pc, PEER_CONNECTION_HANDSHAKE);
        } else {
            JLOG_ERROR("Usage: %s handshake\n", argv[0]);
        }
    } else if (strstr(argv[1], "raw_send")) {
        if (argc == 3) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            peer_connection_dtls_send(&pc->dtls_srtp, argv[2], strlen(argv[2]));
        } else {
            JLOG_ERROR("Usage: %s send message\n", argv[0]);
        }
    } else if (strstr(argv[1], "raw_recv")) {
        if (argc == 3 && atoi(argv[2]) <= BUFFER_SIZE) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            memset(buffer, '\0', BUFFER_SIZE);
            int ret = peer_connection_dtls_recv(&pc->dtls_srtp, buffer, atoi(argv[2]));
            JLOG_INFO("%s recv: %s, %d", pc->name, buffer, ret);
        } else {
            JLOG_ERROR("Usage: %s recv number(max=%d)\n", argv[0], BUFFER_SIZE);
        }
    } else if (strstr(argv[1], "dtls_send")) {
        if (argc == 3) {
            dtls_srtp_write(&pc->dtls_srtp, argv[2], strlen(argv[2]));
        } else {
            JLOG_ERROR("Usage: %s send message\n", argv[0]);
        }
    } else if (strstr(argv[1], "dtls_recv")) {
        if (argc == 3 && atoi(argv[2]) <= BUFFER_SIZE) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            memset(buffer, '\0', BUFFER_SIZE);
            int ret = dtls_srtp_read(&pc->dtls_srtp, buffer, atoi(argv[2]));
            JLOG_INFO("%s recv: %s, %d", pc->name, buffer, ret);
        } else {
            JLOG_ERROR("Usage: %s recv number(max=%d)\n", argv[0], BUFFER_SIZE);
        }
   } else {
        JLOG_ERROR("\nUsage: %s create|start\nUsage: %s set local|remote\nUsage: %s get local|remote", argv[0], argv[0], argv[0]);
   }
}

static void pc_server(int argc, char **argv) {

    if (argc < 2) {
        JLOG_ERROR("\nUsage: %s create|start\nUsage: %s set local|remote\nUsage: %s get local|remote", argv[0], argv[0], argv[0]);
        return;
    }
    peer_connection_t *pc = &peer_connection_server;
    peer_options_t *po = &server_options;
    if (strstr(argv[1], "create")) {
        peer_options_set_default(po, 57000, 58000);
        peer_connection_configure(pc, "peer_server", DTLS_SRTP_ROLE_SERVER, po);
        peer_connection_set_cb_state_change(pc, on_state_change);
        peer_connection_init(pc);
    } else if (strstr(argv[1], "start")) {
            peer_connection_start(pc);
    } else if (strstr(argv[1], "remote")) {
        if (argc == 2) {
            juice_set_remote_description(pc->juice_agent, peer_connection_client.local_sdp.content);
        } else {
            JLOG_ERROR("Usage: %s remote", argv[0]);
        }
   } else if (strstr(argv[1], "push")) {
        if (strstr(argv[2], "offer")) {
            mqtt_offer_publish(pc->local_sdp.content);
        } else if (strstr(argv[2], "answer")) {
            mqtt_answer_publish(pc->local_sdp.content);
        } else {
            JLOG_ERROR("Usage: %s push offer|answer\n", argv[0]);
        }
    } else if (strstr(argv[1], "get")) {
        if (strstr(argv[2], "local")) {
            // juice_get_local_description(pc->juice_agent, pc->local_sdp.content, JUICE_MAX_SDP_STRING_LEN);
            JLOG_INFO("server local description:\n%s\n", pc->local_sdp.content);
        } else if (strstr(argv[2], "remote")) {
            juice_get_remote_description(pc->juice_agent, pc->remote_sdp.content, JUICE_MAX_SDP_STRING_LEN);
            JLOG_INFO("server remote description:\n%s\n", pc->remote_sdp.content);
        } else {
            JLOG_ERROR("Usage: %s get local|remote\n", argv[0]);
        }
    } else if (strstr(argv[1], "pair")) {
        if (argc == 2) {
            if (agent_get_selected_candidate_pair(pc->juice_agent, &pc->local_cand, &pc->remote_cand) == 0) {
                JLOG_INFO("%s local address:", pc->name);
                JLOG_ADDR_RECORD(&pc->local_cand.resolved);
                JLOG_INFO("%s remote address:", pc->name);
                JLOG_ADDR_RECORD(&pc->remote_cand.resolved);
            } else {
                JLOG_ERROR("no selected candidate pair\n", argv[0]);
            }
        } else {
            JLOG_ERROR("Usage: %s pair\n", argv[0]);
        }
    } else if (strstr(argv[1], "state")) {
        if (argc == 3) {
            STATE_CHANGED(pc, atoi(argv[2]));
        } else {
            JLOG_ERROR("Usage: %s state xxx\n", argv[0]);
        }
    } else if (strstr(argv[1], "handshake")) {
        if (argc == 2) {
            JLOG_INFO("%s start handshake:", pc->name);
            JLOG_ADDR_RECORD(&pc->remote_cand.resolved);
            STATE_CHANGED(pc, PEER_CONNECTION_HANDSHAKE);
        } else {
            JLOG_ERROR("Usage: %s handshake\n", argv[0]);
        }
    } else if (strstr(argv[1], "raw_send")) {
        if (argc == 3) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            peer_connection_dtls_send(&pc->dtls_srtp, argv[2], strlen(argv[2]));
        } else {
            JLOG_ERROR("Usage: %s send message\n", argv[0]);
        }
    } else if (strstr(argv[1], "raw_recv")) {
        if (argc == 3 && atoi(argv[2]) <= BUFFER_SIZE) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            memset(buffer, '\0', BUFFER_SIZE);
            int ret = peer_connection_dtls_recv(&pc->dtls_srtp, buffer, atoi(argv[2]));
            JLOG_INFO("%s recv: %s, %d", pc->name, buffer, ret);
        } else {
            JLOG_ERROR("Usage: %s recv number(max=%d)\n", argv[0], BUFFER_SIZE);
        }
    } else if (strstr(argv[1], "dtls_send")) {
        if (argc == 3) {
            dtls_srtp_write(&pc->dtls_srtp, argv[2], strlen(argv[2]));
        } else {
            JLOG_ERROR("Usage: %s send message\n", argv[0]);
        }
    } else if (strstr(argv[1], "dtls_recv")) {
        if (argc == 3 && atoi(argv[2]) <= BUFFER_SIZE) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            memset(buffer, '\0', BUFFER_SIZE);
            int ret = dtls_srtp_read(&pc->dtls_srtp, buffer, atoi(argv[2]));
            JLOG_INFO("%s recv: %s, %d", pc->name, buffer, ret);
        } else {
            JLOG_ERROR("Usage: %s recv number(max=%d)\n", argv[0], BUFFER_SIZE);
        }
   } else {
        JLOG_ERROR("\nUsage: %s create|start\nUsage: %s set local|remote\nUsage: %s get local|remote", argv[0], argv[0], argv[0]);
   }
}

ALIOS_CLI_CMD_REGISTER(pc_server, pc_server, pc_server);
ALIOS_CLI_CMD_REGISTER(pc_client, pc_client, pc_client);
#endif