#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "peer_connection.h"

#define STATE_CHANGED(pc, curr_state) if(pc->cb_state_change && pc->state != curr_state) { pc->cb_state_change(curr_state, pc->user_data); pc->state = curr_state; }

// Turn server config
static juice_turn_server_t turn_server;

/*
static void peer_connection_set_cb_rtp_packet(const uint8_t *packet, size_t bytes, void *user_data) {

  // Buffer **rb = (Buffer**) user_data;

  // if (rb) {

  //   if (utils_buffer_push(rb[1], packet, bytes) == bytes) {

  //     utils_buffer_push(rb[0], (uint8_t*)&bytes, sizeof(bytes));
  //   }
  // }
}
*/

#define PER_TIMEOUT 100 //ms

#define TIMEOUT_COUNT(timeout, per) (((timeout) / (per)) ? ((timeout) / (per)) : 1)

uint32_t rtc_fifo_read_timeout(rtc_fifo_t *fifo, void *outbuf, uint32_t len, uint32_t timeout) {
    uint32_t fifo_len = rtc_fifo_len(fifo);
    uint32_t ret = 0;
    if (len > fifo_len) {
        ret = rtc_fifo_read(fifo, outbuf, fifo_len);
        uint32_t _len = len - fifo_len;
        uint32_t count = TIMEOUT_COUNT(timeout, PER_TIMEOUT);
        while (count > 0 && _len > 0) {
            usleep(1000 * PER_TIMEOUT);
            ret = rtc_fifo_read(fifo, outbuf, _len);
            fifo_len += ret;
            _len -= ret;
            count--;
        }
        return fifo_len;
    } else {
        return rtc_fifo_read(fifo, outbuf, len);
    }
}

int peer_connection_dtls_srtp_recv(void *ctx, char *buf, size_t len) {

    // static const int MAX_RECV = 10000;
    // int recv_max = 0; 
    // int ret; 
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *) ctx; 
    peer_connection_t *pc = (peer_connection_t *) dtls_srtp->user_data;
    return rtc_fifo_read_timeout(&pc->recv_fifo, buf, len, 2000);
}

int peer_connection_dtls_srtp_send(void *ctx, const char *buf, size_t len) {
  
  dtls_srtp_t *dtls_srtp = (dtls_srtp_t *)ctx; 
  peer_connection_t *pc = (peer_connection_t *) dtls_srtp->user_data;

  // //JLOG_DEBUG("send %.4x %.4x, %ld", *(uint16_t*)buf, *(uint16_t*)(buf + 2), len); 
  // return agent_send(pc->juice_agent, buf, len);
  return juice_send(pc->juice_agent, buf, len);
}

static inline char *juice_mode_string(agent_mode_t mode) {
    char *str;
    switch (mode) {
        case AGENT_MODE_CONTROLLING : {
            str = "controlling";
            break;
        }
        case AGENT_MODE_CONTROLLED : {
            str = "controlled";
            break;
        }
        default : {
            str = "unknow";
            break;
        }
    }
    return str;
}

// Agent: on state changed
static void agent_on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
    peer_connection_t *pc = user_ptr;
	JLOG_INFO("%s state: %s\n", pc->name, juice_state_to_string(state));

    if (state == JUICE_STATE_CONNECTED) {
        // Agent 1: on connected, send a message
        // char message[64];
        // memset(message, '\0', 64);
        // snprintf(message, 64, "hello from %s", pc->name);
        // juice_send(agent, message, strlen(message));
        //STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
    }
}

// Agent: on local candidate gathered
static void agent_on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
    peer_connection_t *pc = user_ptr;
	// Filter server reflexive candidates
	// if (strstr(sdp, "host"))
	// 	return;

	JLOG_INFO("%s candidate: %s", pc->name, sdp);

	// Agent: Receive it from agent
	// juice_add_remote_candidate(agent, sdp);
}

// Agent: on local candidates gathering done
static void agent_on_gathering_done(juice_agent_t *agent, void *user_ptr) {
    peer_connection_t *pc = user_ptr;
    juice_get_local_description(pc->juice_agent, pc->local_sdp, JUICE_MAX_SDP_STRING_LEN);
    JLOG_INFO("%s gathering done:\n%s\n", pc->name, pc->local_sdp);
	juice_set_remote_gathering_done(agent); // optional
}

// Agent on message received
static void agent_on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    peer_connection_t *pc = user_ptr;

	char buffer[BUFFER_SIZE];
    snprintf(buffer, size + 1, "%s", data);
    JLOG_INFO( "%s recv: %s, %ld", pc->name, buffer, size);

    rtc_fifo_write(&pc->recv_fifo, data, size);
}

/*
static void peer_connection_incoming_rtcp(peer_connection_t *pc, uint8_t *buf, size_t len) {

  // RtcpHeader rtcp_header = {0};
  // memcpy(&rtcp_header, buf, sizeof(rtcp_header));
  // switch(rtcp_header.type) {
  //   case RTCP_RR:
  //     if(rtcp_header.rc > 0) {
  //       RtcpRr rtcp_rr = rtcp_packet_parse_rr(buf);
  //       uint32_t fraction = ntohl(rtcp_rr.report_block[0].flcnpl) >> 24;
  //       uint32_t total = ntohl(rtcp_rr.report_block[0].flcnpl) & 0x00FFFFFF;
  //       if(pc->on_receiver_packet_loss && fraction > 0) {
  //         pc->on_receiver_packet_loss((float)fraction/256.0, total, pc->user_data);
  //       }
  //     }
  //     break;
  //   default:
  //     break;
  // }
}
*/

void peer_options_set_default(peer_options_t *options, int port_begin, int port_end) {
  // juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

    memset(&turn_server, 0, sizeof(turn_server));
    turn_server.host = TURN_SERVER_HOST;
    turn_server.port = TURN_SERVER_PORT;
    turn_server.username = TURN_SERVER_USERNAME;
    turn_server.password = TURN_SERVER_PASSWORD;

	// Agent: Create config
	juice_config_t *config = &options->juice_config;
	memset(config, 0, sizeof(juice_config_t));
	// Concurrency
	config->concurrency_mode = JUICE_CONCURRENCY_MODE_THREAD;
	// TURN server
	config->turn_servers = &turn_server;
	config->turn_servers_count = 1;
	// Bind address
	config->bind_address = BIND_ADDRESS;
	config->local_port_range_begin = port_begin;
	config->local_port_range_end = port_end;
	// Callback
	config->cb_state_changed = agent_on_state_changed;
	config->cb_candidate = agent_on_candidate;
	config->cb_gathering_done = agent_on_gathering_done;
	config->cb_recv = agent_on_recv;
}

void peer_connection_configure(peer_connection_t *pc, char *name, dtls_srtp_role_t role, peer_options_t *options) {
    options->juice_config.user_ptr = pc; //set user_ptr to pc
    pc->options = *options;
    pc->name = name;
    pc->role = role;
    pc->stack_size = 100*1024;
}


static void peer_connection_loop_run(peer_connection_t *pc) {
    aos_task_new(pc->name, pc->loop, pc, pc->stack_size);
}

static void peer_connection_state_start(peer_connection_t *pc) {

  // int b_video = pc->options.video_codec != CODEC_NONE;
  // int b_audio = pc->options.audio_codec != CODEC_NONE;
  // int b_datachannel = pc->options.datachannel;
  // char *description = (char*)pc->temp_buf;

  // memset(pc->temp_buf, 0, sizeof(pc->temp_buf));

  // agent_reset(pc->juice_agent);

    dtls_srtp_reset_session(&pc->dtls_srtp);

  // pc->sctp.connected = 0;

	juice_get_local_description(pc->juice_agent, pc->local_sdp, JUICE_MAX_SDP_STRING_LEN);
	JLOG_INFO("%s local description:\n%s\n", pc->name, pc->local_sdp);
  
	juice_gather_candidates(pc->juice_agent);
    STATE_CHANGED(pc, PEER_CONNECTION_INIT);
  // agent_gather_candidates(pc->juice_agent);

  // agent_get_local_description(pc->juice_agent, description, sizeof(pc->temp_buf));

  // memset(&pc->local_sdp, 0, sizeof(pc->local_sdp));
  // // TODO: check if we have video or audio codecs
  // sdp_create(&pc->local_sdp, b_video, b_audio, b_datachannel);

  // if (pc->options.video_codec == CODEC_H264) {

  //   sdp_append_h264(&pc->local_sdp);
  //   sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
  //   sdp_append(&pc->local_sdp, "a=setup:actpass");
  //   strcat(pc->local_sdp.content, description);
  // }

  // if (pc->options.audio_codec == CODEC_PCMA) {

  //   sdp_append_pcma(&pc->local_sdp);
  //   sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
  //   sdp_append(&pc->local_sdp, "a=setup:actpass");
  //   strcat(pc->local_sdp.content, description);
  // }

  // if (pc->options.datachannel) {
  //   sdp_append_datachannel(&pc->local_sdp);
  //   sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
  //   sdp_append(&pc->local_sdp, "a=setup:actpass");
  //   strcat(pc->local_sdp.content, description);
  // }

  // pc->b_offer_created = 1;

  // if (pc->onicecandidate) {
  //   pc->onicecandidate(pc->local_sdp.content, pc->user_data);
  // }
}

void peer_connection_loop(void *param) {

//   memset(pc->juice_agent_buf, 0, sizeof(pc->juice_agent_buf));
//   pc->juice_agent_ret = -1;
    peer_connection_t *pc = (peer_connection_t *)param;

    while(1) {
        switch (pc->state) {
            case PEER_CONNECTION_START:

                peer_connection_state_start(pc);
            // if (!pc->b_offer_created) {
            //   peer_connection_state_new(pc);
            // }
            break;

            case PEER_CONNECTION_CONNECTING:
            
            if (agent_get_selected_candidate_pair(pc->juice_agent, &pc->local_cand, &pc->remote_cand) == 0) {
                char address[JUICE_MAX_ADDRESS_STRING_LEN];
                memset(address, 0, JUICE_MAX_ADDRESS_STRING_LEN);
                addr_record_to_string(&pc->local_cand.resolved, address, JUICE_MAX_ADDRESS_STRING_LEN);
                JLOG_INFO("%s local address: %s\n", pc->name, address);
                addr_record_to_string(&pc->remote_cand.resolved, address, JUICE_MAX_ADDRESS_STRING_LEN);
                JLOG_INFO("%s remote address: %s\n", pc->name, address);
                STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
            } else {
                //no avail
            }

            //   if (agent_connectivity_check(pc->juice_agent)) {

            //     JLOG_DEBUG("Connectivity check success. pair: %p", pc->juice_agent.nominated_pair);

            //     STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
            //     pc->juice_agent.selected_pair = pc->juice_agent.nominated_pair;
            //   }

            //   agent_recv(pc->juice_agent, pc->juice_agent_buf, sizeof(pc->juice_agent_buf));

            break;

            case PEER_CONNECTION_CONNECTED:
            if (pc->dtls_srtp.state == DTLS_SRTP_STATE_INIT) {

                if (dtls_srtp_handshake(&pc->dtls_srtp, &pc->remote_cand.resolved) == 0) {

                JLOG_DEBUG("DTLS-SRTP handshake done");

        #ifdef HAVE_GST
                if (pc->audio_stream) {
                    media_stream_play(pc->audio_stream);
                }

                if (pc->video_stream) {
                    media_stream_play(pc->video_stream);
                }
        #endif

                //   if (pc->options.datachannel) {
                //     LOGI("SCTP create socket");
                //     pc->sctp.data_rb = pc->data_rb;
                //     sctp_create_socket(&pc->sctp, &pc->dtls_srtp);
                //   }

                }
            } else if (pc->dtls_srtp.state == DTLS_SRTP_STATE_CONNECTED) {

        //         uint16_t bytes;

        //         if (utils_buffer_pop(pc->audio_rb[0], (uint8_t*)&bytes, sizeof(bytes)) > 0) {
        //           if (utils_buffer_pop(pc->audio_rb[1], pc->juice_agent_buf, bytes) > 0) {
        //             peer_connection_send_rtp_packet(pc, pc->juice_agent_buf, bytes);
        //           }
        //         }
        
        //         if (utils_buffer_pop(pc->video_rb[0], (uint8_t*)&bytes, sizeof(bytes)) > 0) {
        //           if (utils_buffer_pop(pc->video_rb[1], pc->juice_agent_buf, bytes) > 0) {
        //             peer_connection_send_rtp_packet(pc, pc->juice_agent_buf, bytes);
        // 	  }
        //         }
        //         if (utils_buffer_pop(pc->data_rb[0], (uint8_t*)&bytes, sizeof(bytes)) > 0) {
        //           if (utils_buffer_pop(pc->data_rb[1], pc->juice_agent_buf, bytes) > 0) {
        // #if 0
        //   JLOG_INFO("send data: %d\t", bytes);
        //   for (int i = 0; i < 24; ++i) {
        //     JLOG_INFO("%02x ", pc->juice_agent_buf[i]);
        //   }
        //   JLOG_INFO("\n");
        // #endif

        //             dtls_srtp_write(&pc->dtls_srtp, pc->juice_agent_buf, bytes);
        //          }
                }

                // if ((pc->juice_agent_ret = agent_recv(pc->juice_agent, pc->juice_agent_buf, sizeof(pc->juice_agent_buf))) > 0) {
                //   JLOG_DEBUG("agent_recv %d", pc->juice_agent_ret);

                //   if (rtcp_packet_validate(pc->juice_agent_buf, pc->juice_agent_ret)) {
                //     JLOG_DEBUG("Got RTCP packet");
                //     dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, pc->juice_agent_buf, pc->juice_agent_ret);
                //     peer_connection_incoming_rtcp(pc, pc->juice_agent_buf, pc->juice_agent_ret);

                //   } else if (dtls_srtp_validate(pc->juice_agent_buf)) {

                //     int ret = dtls_srtp_read(&pc->dtls_srtp, pc->temp_buf, sizeof(pc->temp_buf));
                //     JLOG_DEBUG("Got DTLS data %d", ret);

                //     if (ret > 0) {
                //       sctp_incoming_data(&pc->sctp, (char*)pc->temp_buf, ret);
                //     }

                //   } else if (rtp_packet_validate(pc->juice_agent_buf, pc->juice_agent_ret)) {
                //     JLOG_DEBUG("Got RTP packet");

                //   }

                // }
            //   }
            break;
            case PEER_CONNECTION_COMPLETED:
            break;
            case PEER_CONNECTION_FAILED:
            break;
            case PEER_CONNECTION_DISCONNECTED:
            break;
            case PEER_CONNECTION_CLOSED:
            break;
            default:
            break;
        }
        aos_msleep(10);
    }
}

void peer_connection_init(peer_connection_t *pc) {

//   uint32_t ssrc;
//   RtpPayloadType type;

// #ifdef HAVE_GST
//   gst_init(NULL, NULL);
// #endif

//   pc->juice_agent.mode = AGENT_MODE_CONTROLLED;

    rtc_fifo_init(&pc->recv_fifo, 1024, 1); //blk size == 1 for bytes fifo
//   memset(&pc->sctp, 0, sizeof(pc->sctp));
    pc->juice_agent = juice_create(&pc->options.juice_config);
    dtls_srtp_init(&pc->dtls_srtp, pc->role, pc);
    pc->dtls_srtp.udp_recv = (mbedtls_ssl_recv_t *)peer_connection_dtls_srtp_recv;
    pc->dtls_srtp.udp_send = (mbedtls_ssl_send_t *)peer_connection_dtls_srtp_send;
    pc->loop = peer_connection_loop;

    peer_connection_loop_run(pc);
//   pc->video_rb[0] = utils_buffer_new(VIDEO_RB_SIZE_LENGTH);
//   pc->video_rb[1] = utils_buffer_new(VIDEO_RB_DATA_LENGTH);
//   pc->audio_rb[0] = utils_buffer_new(AUDIO_RB_SIZE_LENGTH);
//   pc->audio_rb[1] = utils_buffer_new(AUDIO_RB_DATA_LENGTH);
//   pc->data_rb[0] = utils_buffer_new(DATA_RB_SIZE_LENGTH);
//   pc->data_rb[1] = utils_buffer_new(DATA_RB_DATA_LENGTH);

//   if (pc->options.audio_codec) {
// #ifdef HAVE_GST
//     pc->audio_stream = media_stream_create(pc->options.audio_codec,
//      pc->options.audio_outgoing_pipeline, pc->options.audio_incoming_pipeline);
//     pc->audio_stream->outgoing_rb = pc->audio_rb;
// #else
//     rtp_packetizer_init(&pc->audio_packetizer, pc->options.audio_codec,
//      peer_connection_set_cb_rtp_packet, pc->audio_rb);
// #endif
//   }

//   if (pc->options.video_codec) {
// #ifdef HAVE_GST
//     pc->video_stream = media_stream_create(pc->options.video_codec,
//      pc->options.video_outgoing_pipeline, pc->options.video_incoming_pipeline);
//     pc->video_stream->outgoing_rb = pc->video_rb;
// #else
//     rtp_packetizer_init(&pc->video_packetizer, pc->options.video_codec,
//      peer_connection_set_cb_rtp_packet, pc->video_rb);
// #endif
//   }

}

int peer_connection_send_audio(peer_connection_t *pc, const uint8_t *buf, size_t len) {
// #ifndef HAVE_GST
//   if (pc->dtls_srtp.state == DTLS_SRTP_STATE_CONNECTED) {
//     rtp_packetizer_encode(&pc->audio_packetizer, (uint8_t*)buf, len);
//   }
// #endif
  return 0;
}

int peer_connection_send_video(peer_connection_t *pc, const uint8_t *buf, size_t len) {
// #ifndef HAVE_GST
//   if (pc->dtls_srtp.state == DTLS_SRTP_STATE_CONNECTED) {
//     rtp_packetizer_encode(&pc->video_packetizer, (uint8_t*)buf, len);
//   }
// #endif
  return 0;
}

int peer_connection_datachannel_send(peer_connection_t *pc, char *message, size_t len) {

//   if(!sctp_is_connected(&pc->sctp)) {
//     LOGE("sctp not connected");
//     return -1;
//   }

//   return sctp_outgoing_data(&pc->sctp, message, len, PPID_STRING);
return 0;
}

int peer_connection_datachannel_send_binary(peer_connection_t *pc, char *message, size_t len) {

//   if(!sctp_is_connected(&pc->sctp)) {
//     LOGE("sctp not connected");
//     return -1;
//   }

//   return sctp_outgoing_data(&pc->sctp, message, len, PPID_BINARY);
return 0;
}

void peer_connection_set_remote_description(peer_connection_t *pc, const char *sdp) {

  juice_set_remote_description(pc->juice_agent, sdp);
  STATE_CHANGED(pc, PEER_CONNECTION_CONNECTING);
}

void peer_connection_add_remote_candidate(peer_connection_t *pc, const char *sdp) {
  juice_add_remote_candidate(pc->juice_agent, sdp);
  STATE_CHANGED(pc, PEER_CONNECTION_CONNECTING);
}

void peer_connection_start(peer_connection_t *pc) {

  STATE_CHANGED(pc, PEER_CONNECTION_START);
  // pc->b_offer_created = 0;
}

int peer_connection_send_rtp_packet(peer_connection_t *pc, uint8_t *packet, int bytes) {

  // dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, packet, &bytes);

  // return agent_send(pc->juice_agent, packet, bytes);
  return 0;
}

int peer_connection_send_rtcp_pil(peer_connection_t *pc, uint32_t ssrc) {

  // int ret = -1;
  // uint8_t plibuf[128];
  // rtcp_packet_get_pli(plibuf, 12, ssrc);
 
  // //TODO: encrypt rtcp packet
  // //guint size = 12;
  // //dtls_transport_encrypt_rctp_packet(pc->dtls_transport, plibuf, &size);
  // //ret = nice_agent_send(pc->nice_agent, pc->stream_id, pc->component_id, size, (gchar*)plibuf);

  // return ret;
  return 0;
}

// callbacks
void peer_connection_set_cb_connected(peer_connection_t *pc, void (*on_connected)(void *userdata)) {

  pc->cb_connected = on_connected;
}

void peer_connection_set_cb_receiver_packet_loss(peer_connection_t *pc,
 void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void *userdata)) {

  pc->cb_receiver_packet_loss = on_receiver_packet_loss;
}

void peer_connection_set_cb_candidate(peer_connection_t *pc, void (*on_candidate)(char *sdp_text, void *userdata)) {

  pc->cb_candidate = on_candidate;
}

void peer_connection_set_cb_state_change(peer_connection_t *pc,
 void (*on_state_change)(peer_connection_state_t state, void *userdata)) {

  pc->cb_state_change = on_state_change;
}

void peer_connection_set_cb_track(peer_connection_t *pc, void (*on_track)(uint8_t *packet, size_t byte, void *userdata)) {

  pc->cb_track = on_track;
}

void peer_connection_set_cbdatachannel(peer_connection_t *pc,
 void (*onmessasge)(char *msg, size_t len, void *userdata),
 void (*onopen)(void *userdata),
 void (*onclose)(void *userdata)) {

  // if (pc) {

  //   sctp_onopen(&pc->sctp, onopen);
  //   sctp_onclose(&pc->sctp, onclose);
  //   sctp_onmessage(&pc->sctp, onmessasge);
  // }
}

void peer_connection_set_current_ip(const char *ip) {

  // ports_set_current_ip(ip);
}
