//#include "test_config.h"
#include <cJSON.h>
#include "peer_connection.h"
#include "udp.h"
#include "rtp_enc.h"
#include "pipe.h"
#include "log.h"

#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
#include <aos/kernel.h>
#include <lwip/stats.h>


extern void mqtt_offer_publish(char *sdp_content);
extern void mqtt_answer_publish(char *sdp_content);

char buffer[BUFFER_SIZE];

peer_connection_t peer_connection_server, peer_connection_client;
peer_options_t server_options, client_options;

static void on_channel_msg(char *msg, size_t len, uint16_t si, void *userdata) {
    peer_connection_t *pc = (peer_connection_t *)userdata;
    JLOG_INFO("%s channel %d msg(%d): %s", pc->name, si, len, msg);
}

static void on_pipe_push_answer(char *sdp_content, void *userdata) {
    peer_connection_t *pc = (peer_connection_t *)userdata;
    JLOG_INFO("%s answer: %s", pc->name, sdp_content);
    cJSON *signal = cJSON_CreateObject();
    cJSON_AddStringToObject(signal, "type", "answer");
    cJSON_AddStringToObject(signal, "sdp", sdp_content);
    char *signal_string = cJSON_Print(signal);
    pipe_send(signal_string, strlen(signal_string));
    // aos_msleep(1000);
    cJSON_Delete(signal);
}

static void on_pipe_push_candidate(char *sdp_content, void *userdata) {
    peer_connection_t *pc = (peer_connection_t *)userdata;
    JLOG_INFO("%s candidate: %s", pc->name, sdp_content);
    cJSON *signal = cJSON_CreateObject();
    cJSON_AddStringToObject(signal, "type", "candidate");
    cJSON_AddStringToObject(signal, "candidate", sdp_content);
    cJSON_AddNumberToObject(signal, "sdpMLineIndex", 0);
    cJSON_AddStringToObject(signal, "sdpMid", "0");
    char *signal_string = cJSON_Print(signal);
    pipe_send(signal_string, strlen(signal_string));
    // aos_msleep(1000);
    cJSON_Delete(signal);
}

static void on_channel_open(void *userdata) {
    peer_connection_t *pc = (peer_connection_t *)userdata;
    JLOG_INFO("%s channel open", pc->name);
}

static void on_channel_close(void *userdata) {
    peer_connection_t *pc = (peer_connection_t *)userdata;
    JLOG_INFO("%s channel close", pc->name);
}

static void on_state_change(peer_connection_state_t state, void *userdata) {
    peer_connection_t *pc = (peer_connection_t *)userdata;
    JLOG_INFO("%s state is changed: %d", pc->name, state);
}
static void on_receiver_packet_loss(uint32_t ssrc, float fraction_loss, uint32_t total_loss, void *userdata) {
    peer_connection_t *pc = (peer_connection_t *)userdata;
    JLOG_INFO("%s receiver packet: ssrc(%d), fraction_loss(%f) total_loss(%d)", pc->name, ssrc, fraction_loss, total_loss);
}


static void pc_cli_process(int argc, char **argv, char *pc_name, peer_connection_t *pc, peer_options_t *po, int role, peer_connection_t *pc_remote) {

    if (argc < 2) {
        JLOG_ERROR("Usage: %s create|start|remote|pair\n", argv[0]);
        JLOG_ERROR("Usage: %s get local|remote\n", argv[0]);
        JLOG_ERROR("Usage: %s rtp_enc init|start|stop|restart\n", argv[0]);
        JLOG_ERROR("Usage: %s push offer|answer\n", argv[0]);
        JLOG_ERROR("Usage: %s state xxx\n", argv[0]);
        JLOG_ERROR("Usage: %s handshake\n", argv[0]);
        JLOG_ERROR("Usage: %s send raw|dtls message\n", argv[0]);
        JLOG_ERROR("Usage: %s recv raw|dtls number(max=%d)\n", argv[0], BUFFER_SIZE);
        JLOG_ERROR("Usage: %s send ch si message\n", argv[0]);
        JLOG_ERROR("Usage: %s rtp_stats\n", argv[0]);
        JLOG_ERROR("Usage: %s juice_destroy\n", argv[0]);
        JLOG_ERROR("Usage: %s mem_stats\n", argv[0]);
        JLOG_ERROR("Usage: %s memp_stats all/[0-%d]\n", argv[0], MEMP_MAX);
        return;
    }

    if (strstr(argv[1], "create")) {
        pipe_create("pipe_client", pc);
        peer_options_set_default(po, 57000, 58000);
        peer_connection_configure(pc, pc_name, role, po);
        peer_connection_set_cb_state_change(pc, on_state_change);
        peer_connection_set_datachannel_cb(pc, pc, on_channel_msg, on_channel_open, on_channel_close);
        peer_connection_set_cb_receiver_packet_loss(pc, on_receiver_packet_loss);
        peer_connection_set_cb_push_answer(pc, on_pipe_push_answer);
        peer_connection_set_cb_push_candidate(pc, on_pipe_push_candidate);
        peer_connection_init(pc);
    } else if (strstr(argv[1], "start")) {
            peer_connection_start(pc);
    } else if (strstr(argv[1], "gather")) {
            juice_gather_candidates(pc->juice_agent);
    } else if (strstr(argv[1], "remote")) {
        if (argc == 2) {
            juice_set_remote_description(pc->juice_agent, pc_remote->local_sdp.content);
        } else {
            JLOG_ERROR("Usage: %s remote", argv[0]);
        }
   } else if (strstr(argv[1], "rtp_enc")) {
        if (strstr(argv[2], "init")) {
            rtp_enc_init(pc);
        } else if (strstr(argv[2], "start")) {
            rtp_enc_start(pc);
        } else if (strstr(argv[2], "stop")) {
            rtp_enc_stop(pc);
        } else if (strstr(argv[2], "restart")) {
            rtp_enc_restart(pc);
        } else {
            JLOG_ERROR("Usage: %s rtp_enc init|start|stop|restart\n", argv[0]);
        }
   } else if (strstr(argv[1], "rtp_dec")) {
        if (strstr(argv[2], "init")) {
            rtp_dec_init(pc);
        } else if (strstr(argv[2], "start")) {
            rtp_dec_start(pc);
        } else if (strstr(argv[2], "stop")) {
            rtp_dec_stop(pc);
        } else if (strstr(argv[2], "restart")) {
            rtp_dec_restart(pc);
        } else {
            JLOG_ERROR("Usage: %s rtp_enc init|start|stop|restart\n", argv[0]);
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
    } else if (strstr(argv[1], "handshake")) {
        if (argc == 2) {
            JLOG_INFO("%s start handshake:", pc->name);
            JLOG_ADDR_RECORD(&pc->remote_cand.resolved);
            STATE_CHANGED(pc, PEER_CONNECTION_HANDSHAKE);
        } else {
            JLOG_ERROR("Usage: %s handshake\n", argv[0]);
        }
    } else if (strstr(argv[1], "send")) {
        if (argc >= 4) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            if (strstr(argv[2], "raw")) {
                peer_connection_dtls_send(&pc->dtls_srtp, argv[2], strlen(argv[2]));
            } else if (strstr(argv[2], "dtls")) {
                 dtls_srtp_write(&pc->dtls_srtp, argv[2], strlen(argv[2]));
            } else if (strstr(argv[2], "ch")) {
                if (argc == 5) {
                    peer_connection_datachannel_send(pc, atoi(argv[3]), argv[4], strlen(argv[4]));
                } else {
                    JLOG_ERROR("Usage: %s send ch si message\n", argv[0]);
                }
            } else {
                JLOG_ERROR("Usage: %s send raw|dtls message\n", argv[0]);
                JLOG_ERROR("Usage: %s send ch si message\n", argv[0]);
            }
        } else {
            JLOG_ERROR("Usage: %s send raw|dtls message\n", argv[0]);
            JLOG_ERROR("Usage: %s send ch si message\n", argv[0]);
        }
    } else if (strstr(argv[1], "recv")) {
        if (argc >= 3) {
            // juice_send(pc->juice_agent, argv[2], strlen(argv[2]));
            if (strstr(argv[2], "raw") && atoi(argv[2]) <= BUFFER_SIZE) {
                memset(buffer, '\0', BUFFER_SIZE);
                int ret = peer_connection_dtls_recv(&pc->dtls_srtp, buffer, atoi(argv[2]));
                JLOG_INFO_DUMP_HEX(buffer, ret, "------------%s recv: %s, %d---------------", pc->name, buffer, ret);
            } else if (strstr(argv[2], "dtls") && atoi(argv[2]) <= BUFFER_SIZE) {
                memset(buffer, '\0', BUFFER_SIZE);
                int ret = dtls_srtp_read(&pc->dtls_srtp, buffer, atoi(argv[2]));
                JLOG_INFO_DUMP_HEX(buffer, ret, "------------%s recv: %s, %d-----------", pc->name, buffer, ret);
            } else {
                JLOG_ERROR("Usage: %s recv raw|dtls number(max=%d)\n", argv[0], BUFFER_SIZE);
            }
        } else {
            JLOG_ERROR("Usage: %s recv raw|dtls number(max=%d)\n", argv[0], BUFFER_SIZE);
        }
    } else if (strstr(argv[1], "rtp_stats")) {
        if (argc == 2) {
            JLOG_INFO("rtp_tx_cache_list count[%d:%d], memused:[%d:%d]KB",
                      rtp_list_count(&pc->rtp_tx_cache_list), pc->rtp_tx_cache_list.max_size,
                      rtp_list_memused(&pc->rtp_tx_cache_list) / 1000, rtp_list_memused_max_size(&pc->rtp_tx_cache_list) / 1000);
            JLOG_INFO("rtp_rtx_cache_list count[%d:%d], memused:[%d:%d]KB",
                      rtp_list_count(&pc->rtp_rtx_cache_list), pc->rtp_rtx_cache_list.max_size,
                      rtp_list_memused(&pc->rtp_rtx_cache_list) / 1000, rtp_list_memused_max_size(&pc->rtp_rtx_cache_list) / 1000);
            JLOG_INFO("rtp_recv_cache_list count[%d:%d], memused:[%d:%d]KB",
                      rtp_list_count(&pc->rtp_recv_cache_list), pc->rtp_recv_cache_list.max_size,
                      rtp_list_memused(&pc->rtp_recv_cache_list) / 1000, rtp_list_memused_max_size(&pc->rtp_recv_cache_list) / 1000);
        } else {
            JLOG_ERROR("Usage: %s rtp_stats\n", argv[0]);
        }
    } else if (strstr(argv[1], "juice_destroy")) {
        if (argc == 2) {
            juice_destroy(pc->juice_agent);
            // JLOG_INFO("rtp_tx_cache_list count:%d", rtp_list_count(&pc->rtp_tx_cache_list));
        } else {
            JLOG_ERROR("Usage: %s juice_destroy\n", argv[0]);
        }
    } else if (strstr(argv[1], "mem_stats")) {
        if (argc == 2) {
            MEM_STATS_DISPLAY();
            // JLOG_INFO("rtp_tx_cache_list count:%d", rtp_list_count(&pc->rtp_tx_cache_list));
        } else {
            JLOG_ERROR("Usage: %s mem_stats\n", argv[0]);
        }
    } else if (strstr(argv[1], "memp_stats")) {
        if (argc == 3) {
             if (strstr(argv[2], "all")) {
                for (int i=0; i<MEMP_MAX; i++) {
                    MEMP_STATS_DISPLAY(i);
                }
             } else {
                MEMP_STATS_DISPLAY(atoi(argv[2]));
             }
            // JLOG_INFO("rtp_tx_cache_list count:%d", rtp_list_count(&pc->rtp_tx_cache_list));
        } else {
            JLOG_ERROR("Usage: %s memp_stats all/[0-%d]\n", argv[0], MEMP_MAX);
        }
    } else {
        JLOG_ERROR("Usage: %s create|start|remote|pair\n", argv[0]);
        JLOG_ERROR("Usage: %s get local|remote\n", argv[0]);
        JLOG_ERROR("Usage: %s rtp_enc init|start|stop|restart\n", argv[0]);
        JLOG_ERROR("Usage: %s push offer|answer\n", argv[0]);
        JLOG_ERROR("Usage: %s state xxx\n", argv[0]);
        JLOG_ERROR("Usage: %s handshake\n", argv[0]);
        JLOG_ERROR("Usage: %s send raw|dtls message\n", argv[0]);
        JLOG_ERROR("Usage: %s recv raw|dtls number(max=%d)\n", argv[0], BUFFER_SIZE);
        JLOG_ERROR("Usage: %s send ch si message\n", argv[0]);
        JLOG_ERROR("Usage: %s rtp_stats\n", argv[0]);
        JLOG_ERROR("Usage: %s juice_destroy\n", argv[0]);
        JLOG_ERROR("Usage: %s mem_stats\n", argv[0]);
        JLOG_ERROR("Usage: %s memp_stats all/[0-%d]\n", argv[0], MEMP_MAX);
    }
}

static void pc_client(int argc, char **argv) {

    peer_connection_t *pc = &peer_connection_client;
    peer_connection_t *pc_remote = &peer_connection_server;
    peer_options_t *po = &client_options;
    pc_cli_process(argc, argv, "peer_client", pc, po, DTLS_SRTP_ROLE_CLIENT, pc_remote);
}

static void pc_server(int argc, char **argv) {
    peer_connection_t *pc = &peer_connection_server;
    peer_connection_t *pc_remote = &peer_connection_client;
    peer_options_t *po = &server_options;
    pc_cli_process(argc, argv, "peer_server", pc, po, DTLS_SRTP_ROLE_SERVER, pc_remote);
}

ALIOS_CLI_CMD_REGISTER(pc_server, pc_server, pc_server);
ALIOS_CLI_CMD_REGISTER(pc_client, pc_client, pc_client);
#endif