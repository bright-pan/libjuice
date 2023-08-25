#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include "peer_connection.h"
#include "rtcp_packet.h"

// #define STATE_CHANGED(pc, curr_state) if(pc->cb_state_change && pc->state != curr_state) { pc->cb_state_change(curr_state, pc->user_data); pc->state = curr_state; }


#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define bits_mask(i) (1 << (i))

// Turn server config
static juice_turn_server_t turn_server;

int peer_connection_send_rtp_frame(peer_connection_t *pc, int pid) {
    int ret = -1;

    rtp_list_wlock(&pc->rtp_cache_list);
    rtp_frame_t *frame = rtp_list_find_by_seq(&pc->rtp_cache_list, pid);
    if (frame) {
        JLOG_INFO("resend pid[%d]:%d", pid, frame->bytes);
        // frame->timeout_count--;
        juice_send(pc->juice_agent, frame->packet, frame->bytes);
        if (ret == JUICE_ERR_SUCCESS) {
            ret = frame->bytes;
        }
        // resend
        if (frame->resend_count-- < 0) {
            rtp_list_delete(&pc->rtp_cache_list, frame);
        }
    }
    rtp_list_unlock(&pc->rtp_cache_list);
    return ret;
}

void peer_connection_rtp_frame_lost_process(peer_connection_t *pc, int pid, uint16_t lostmap) {

    peer_connection_send_rtp_frame(pc, pid++);

    if (lostmap) {
        for (int i = 0; i < 16; i++) {
            if (lostmap & bits_mask(i)) {
                // pid_array[i+1] = pid++;
                peer_connection_send_rtp_frame(pc, pid + i);
            }
        }
    }
}

static void peer_connection_incoming_rtcp(peer_connection_t *pc, uint8_t *buf, size_t len) {

    rtcp_header_t rtcp_header = {0};
    size_t rtcp_len,offset = 0;
    uint8_t *rtcp_buf;

    while(offset + sizeof(rtcp_header_t) <= len) {
        rtcp_buf = buf + offset;
        memcpy(&rtcp_header, rtcp_buf, sizeof(rtcp_header_t));
        rtcp_len = (ntohs(rtcp_header.length) + 1) * 4;
        // JLOG_INFO("parse rtcp[%d]:", rtcp_len);
        // JLOG_INFO_DUMP_HEX(rtcp_buf, rtcp_len, "rtcp_type:%d", rtcp_header.type);
        if (offset + rtcp_len <= len) {
            switch(rtcp_header.type) {
                case RTCP_RR: {
                    if(rtcp_header.rc > 0) {
                        rtcp_rr_t rtcp_rr = rtcp_packet_parse_rr(rtcp_buf);
                        uint32_t fraction = ntohl(rtcp_rr.report_block[0].flcnpl) >> 24;
                        uint32_t total = ntohl(rtcp_rr.report_block[0].flcnpl) & 0x00FFFFFF;
                        if(pc->cb_receiver_packet_loss && fraction > 0) {
                            pc->cb_receiver_packet_loss((float)fraction/256.0, total, pc);
                        }
                    }
                    break;
                }
                case RTCP_RTPFB: {
                    switch (rtcp_header.rc) {
                        case RTCP_FMT_RTPFB_NACK: {
                            rtcp_rtpfb_nack_t rtpfb_nack = rtcp_packet_parse_rtpfb_nack(rtcp_buf);
                            uint16_t nack_block_size = ntohs(rtpfb_nack.header.length) - 2;
                            uint32_t ssrc_ps = ntohl(rtpfb_nack.ssrc_ps);
                            uint32_t ssrc_ms = ntohl(rtpfb_nack.ssrc_ms);
                            for (int i = 0; i < nack_block_size; i++) {
                                uint16_t pid = ntohs(rtpfb_nack.nack_block[0].pid);
                                uint16_t lostmap = ntohs(rtpfb_nack.nack_block[0].lostmap);
                                // JLOG_INFO("pid:%d, lostmap:%04X, ssrc_ps:%d, ssrc_ms:%d", pid, lostmap, ssrc_ps, ssrc_ms);
                                peer_connection_rtp_frame_lost_process(pc, pid, lostmap);
                            }
                            break;
                        }
                        default: {
                            JLOG_ERROR("unknow rtpfb fmt[%d] for parse", rtcp_header.type);
                            break;
                        }
                    }
                    break;
                }
                case RTCP_PSFB: {
                    switch (rtcp_header.rc) {
                        case RTCP_FMT_PSFB_PLI: {
                            rtcp_psfb_pli_t psfb_pli = rtcp_packet_parse_psfb_pli(rtcp_buf);
                            uint32_t ssrc_ps = ntohl(psfb_pli.pli_block[0].ssrc_ps);
                            uint32_t ssrc_ms = ntohl(psfb_pli.pli_block[0].ssrc_ms);
                            JLOG_INFO("ssrc_ps:%d, ssrc_ms:%d", ssrc_ps, ssrc_ms);
                            break;
                        }
                        case RTCP_FMT_PSFB_REMB: {
                            rtcp_psfb_remb_t psfb_remb = rtcp_packet_parse_psfb_remb(rtcp_buf);
                            uint32_t ssrc_ps = ntohl(psfb_remb.remb_block[0].ssrc_ps);
                            uint32_t ssrc_ms = ntohl(psfb_remb.remb_block[0].ssrc_ms);
                            uint32_t remb = ntohl(psfb_remb.remb_block[0].remb);
                            uint32_t ssrc_feedback = ntohl(psfb_remb.remb_block[0].ssrc_feedback);
                            br_union_t br;
                            br.value = ntohl(psfb_remb.remb_block[0].br.value);
                            uint32_t num_ssrc = psfb_remb.remb_block[0].br.s.num_ssrc;
                            uint32_t exp = psfb_remb.remb_block[0].br.s.exp;
                            uint32_t mantissa = psfb_remb.remb_block[0].br.s.mantissa;
                            // uint32_t num_ssrc = psfb_remb.remb_block[0].num_ssrc;
                            // uint32_t exp = psfb_remb.remb_block[0].exp;
                            // uint32_t mantissa = psfb_remb.remb_block[0].mantissa;
                            JLOG_DEBUG("ssrc_ps:%d, ssrc_ms:%d, remb:%08X, num_ssrc:%d, br: %fkBps, ssrc_feedback:%d",
                                        ssrc_ps, ssrc_ms, remb, num_ssrc, pow(2, exp) * mantissa / 1000, ssrc_feedback);

                            break;
                        }
                        default: {
                            JLOG_ERROR_DUMP_HEX(rtcp_buf, rtcp_len, "-----------unknow psfb fmt[%d] for parse, rtcp_buf[%d]------------", rtcp_header.type, rtcp_len);
                            break;
                        }
                    }
                    break;
                }
                default: {
                    JLOG_ERROR_DUMP_HEX(rtcp_buf, rtcp_len, "--------------unknow rtcp type[%d] parse, rtcp_buf[%d]-----------", rtcp_header.type);
                    break;
                }
            }
            offset += rtcp_len;
        } else {
            break;
        }
    }
}

static void peer_connection_set_cb_rtp_packet(char *packet, int bytes, void *user_data) {

    peer_connection_t *pc = user_data;
    dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, (char *)packet, &bytes);
    // JLOG_INFO("add rtp frame[%d]", seq_number);
    rtp_frame_t *frame = rtp_frame_malloc(ntohs(((rtp_header_t *)packet)->seq_number), packet, bytes);
    if (frame) {
        rtp_list_wlock(&pc->rtp_send_list);
        if (rtp_list_insert(&pc->rtp_send_list, frame) < 0) {
            rtp_frame_free(frame);
        }
        rtp_list_unlock(&pc->rtp_send_list);
    }
}

static void *rtp_process_thread_entry(void *args)
{
    int ret = 0;
    rtp_frame_t *frame;
    rtp_frame_t *tmp;
    peer_connection_t *pc = args;

    thread_set_name_self("rtp_process");

    while (1) {
        rtp_list_wlock(&pc->rtp_send_list);
        HASH_ITER(hh, pc->rtp_send_list.utlist, frame, tmp) {
            // send data
            juice_send(pc->juice_agent, frame->packet, frame->bytes);
            frame->resend_count--;
            rtp_list_pop(&pc->rtp_send_list, frame);
            // insert to cache;
            rtp_list_wlock(&pc->rtp_cache_list);
            if (rtp_list_insert(&pc->rtp_cache_list, frame) < 0) {
                rtp_frame_free(frame);
            }
            rtp_list_unlock(&pc->rtp_cache_list);
        }
        rtp_list_unlock(&pc->rtp_send_list);
        rtp_list_wlock(&pc->rtp_cache_list);
        HASH_ITER(hh, pc->rtp_cache_list.utlist, frame, tmp) {
            if (frame->timeout_count-- <= 0) {
                rtp_list_delete(&pc->rtp_cache_list, frame);
            }
        }
        rtp_list_unlock(&pc->rtp_cache_list);
        usleep(RTP_FRAME_INTERVAL*1000);
    }
    pthread_exit(&ret);
    return NULL;
}

int peer_connection_rtp_process_thread_init(peer_connection_t *pc, void *(*thread_entry)(void *)) {
    int ret = -1;
    thread_attr_t attr;

    if (pc->rtp_process_thread == NULL) {
        thread_attr_init(&attr, pc->rtp_process_thread_prio, pc->rtp_process_thread_ssize);
        ret = thread_init_ex(&pc->rtp_process_thread, &attr, thread_entry, pc);
        if (ret != 0) {
            JLOG_ERROR("rtp process thread created failure!");
        } else {
            JLOG_INFO("rtp process thread created!");
        }
    } else {
        JLOG_ERROR("rtp process has beed created!");
    }
    return ret;
}

#define PER_TIMEOUT 100 //ms

#define TIMEOUT_COUNT(timeout, per) (((timeout) / (per)) ? ((timeout) / (per)) : 1)

/*
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
*/

int peer_connection_dtls_recv(void *ctx, char *buf, size_t len) {
    int recv_count;
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *) ctx; 
    peer_connection_t *pc = (peer_connection_t *) dtls_srtp->user_data;
    uint32_t timeout_count = TIMEOUT_COUNT(pc->recv_timeout, PER_TIMEOUT);

    while (timeout_count > 0) {
        // recv_count = msg_fifo_read(&pc->msg_fifo, &recv_frame);
        recv_count = packet_fifo_read(&pc->dtls_fifo, buf, len);
        if (recv_count > 0) {
            // recv_count = MIN(len, recv_frame.data_size);
            // memcpy(buf, recv_frame.data, recv_count);
            return recv_count;
        } else {
            // no data
            usleep(1000 * PER_TIMEOUT);
            timeout_count--;
        }
    }
    return MBEDTLS_ERR_SSL_WANT_READ;
}
/*
extern int dtls_srtp_udp_recv(void *ctx, char *buf, size_t len);

int peer_connection_dtls_srtp_recv(void *ctx, char *buf, size_t len) {
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *) ctx;
    return dtls_srtp_udp_recv(dtls_srtp, buf, len);
}
*/
int peer_connection_dtls_send(void *ctx, const char *buf, size_t len) {
    int ret;
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *)ctx; 
    peer_connection_t *pc = (peer_connection_t *) dtls_srtp->user_data;

    // //JLOG_DEBUG("send %.4x %.4x, %ld", *(uint16_t*)buf, *(uint16_t*)(buf + 2), len); 
    // return agent_send(pc->juice_agent, buf, len);
    ret = juice_send(pc->juice_agent, buf, len);
    if (ret == JUICE_ERR_SUCCESS) {
        return len;
    } else {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
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

    switch (state) {
        case JUICE_STATE_CONNECTED: {
            STATE_CHANGED(pc, PEER_CONNECTION_CONNECTING);
            break;
        }
        case JUICE_STATE_FAILED: {
            STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
            pc->dtls_srtp.state = DTLS_SRTP_STATE_INIT;
            break;
        }
        default :{
            JLOG_ERROR("%s state: %s is not process\n", pc->name, juice_state_to_string(state));
            break;
        }
    }
}

extern void mqtt_candidate_publish(char *sdp_content);
// Agent: on local candidate gathered
static void agent_on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
    peer_connection_t *pc = user_ptr;
    // Filter server reflexive candidates
    // if (strstr(sdp, "host"))
    // 	return;

    JLOG_INFO("%s candidate: %s", pc->name, sdp);

    mqtt_candidate_publish((char *)&sdp[2]);
    // sdp_append(&pc->local_sdp, sdp);
    // Agent: Receive it from agent
    // juice_add_remote_candidate(agent, sdp);
}

// Agent: on local candidates gathering done
static void agent_on_gathering_done(juice_agent_t *agent, void *user_ptr) {
    peer_connection_t *pc = user_ptr;
    // juice_get_local_description(pc->juice_agent, pc->local_sdp.content, JUICE_MAX_SDP_STRING_LEN);
    JLOG_INFO("%s gathering done:\n%s\n", pc->name, pc->local_sdp.content);
    juice_set_remote_gathering_done(agent); // optional

    // answer
    // STATE_CHANGED(pc, PEER_CONNECTION_START);
}

// Agent on message received
static void agent_on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    char buf[4096];
    int ret, bytes;
    peer_connection_t *pc = user_ptr;
    if((data[0]>=128) && (data[0]<=191)) {
        // JLOG_INFO( "%s recv rtp: %ld", pc->name, size);
        memcpy(buf, data, size);
        bytes = size;
        if (rtcp_packet_validate((uint8_t *)buf, bytes)) {
            ret = dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, buf, &bytes);
            if (ret == srtp_err_status_ok) {
                // JLOG_INFO("rtcp packet[%d]:", bytes);
                // JLOG_INFO_DUMP_HEX(buf, bytes);
                peer_connection_incoming_rtcp(pc, (uint8_t *)buf, bytes);
            } else {
                JLOG_INFO_DUMP_HEX(data, size, "--------------invalid[%d] rtcp packet[%d]---------------", ret, size);
            }
        } else {
            ret = dtls_srtp_decrypt_rtp_packet(&pc->dtls_srtp, buf, &bytes);
            if (ret == srtp_err_status_ok) {
                // JLOG_INFO("rtp packet[%d]:", bytes);
                // JLOG_INFO_DUMP_HEX(buf, bytes);
            } else {
                JLOG_INFO_DUMP_HEX(data, size, "--------------invalid[%d] rtp packet[%d]---------------", ret, size);
            }
        }
        //packet_fifo_write(&pc->rtp_fifo, (char *)data, size);
        return;
    }
    if((data[0]>=20)  && (data[0]<=64)) {
        // JLOG_INFO( "%s recv dtls: %ld", pc->name, size);
        packet_fifo_write(&pc->dtls_fifo, (char *)data, size);
        return;
    }

    JLOG_INFO( "%s recv other: %ld", pc->name, size);
    packet_fifo_write(&pc->other_fifo, (char *)data, size);
}

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
    pc->options.video_codec = MEDIA_CODEC_H264;
    pc->options.audio_codec = MEDIA_CODEC_NONE;
    pc->options.datachannel = 1;

    // pc loop
    pc->loop_thread = NULL;
    pc->loop_thread_ssize = 50*1024;
    pc->loop_thread_prio = 31;    
    
    // rtp process
    pc->rtp_process_thread = NULL;
    pc->rtp_process_thread_ssize = 50*1024;
    pc->rtp_process_thread_prio = 31;

    // rtp encode
    pc->rtp_enc_thread = NULL;
    pc->rtp_enc_thread_ssize = 30*1024;
    pc->rtp_enc_thread_prio = 31;
}

static int peer_connection_loop_thread_init(peer_connection_t *pc, void *(*thread_entry)(void *)) {
    int ret = -1;
    thread_attr_t attr;

    if (pc->loop_thread == NULL) {
        thread_attr_init(&attr, pc->loop_thread_prio, pc->loop_thread_ssize);
        ret = thread_init_ex(&pc->loop_thread, &attr, thread_entry, pc);
        if (ret != 0) {
            JLOG_ERROR("loop thread created failure!");
        } else {
            JLOG_INFO("loop thread %s created!", pc->name);
        }
    } else {
        JLOG_ERROR("loop thread has beed created!");
    }
    return ret;
}

extern void mqtt_answer_publish(char *sdp_content);


static void peer_connection_state_start(peer_connection_t *pc) {

    int b_video = pc->options.video_codec != MEDIA_CODEC_NONE;
    int b_audio = pc->options.audio_codec != MEDIA_CODEC_NONE;
    int b_datachannel = pc->options.datachannel;
    char description[SDP_CONTENT_LENGTH];
    memset(description, '\0', SDP_CONTENT_LENGTH);

  // agent_reset(pc->juice_agent);

    dtls_srtp_reset_session(&pc->dtls_srtp);

    pc->sctp.connected = 0;

    juice_gather_candidates(pc->juice_agent);
    juice_get_local_description(pc->juice_agent, description, SDP_CONTENT_LENGTH);

    sdp_reset(&pc->local_sdp);
    // // TODO: check if we have video or audio codecs
    sdp_create(&pc->local_sdp, b_video, b_audio, b_datachannel);


    if (pc->options.video_codec == MEDIA_CODEC_H264) {

        sdp_append_h264(&pc->local_sdp);
        sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
        if (pc->role == DTLS_SRTP_ROLE_SERVER) {
            sdp_append(&pc->local_sdp, "a=setup:actpass");
        } else {
            sdp_append(&pc->local_sdp, "a=setup:active");
        }
        strcat(pc->local_sdp.content, description);
    }

    if (pc->options.datachannel) {
        sdp_append_datachannel(&pc->local_sdp);
        sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
        if (pc->role == DTLS_SRTP_ROLE_SERVER) {
            sdp_append(&pc->local_sdp, "a=setup:actpass");
        } else {
            sdp_append(&pc->local_sdp, "a=setup:active");
        }
        strcat(pc->local_sdp.content, description);
    }

    if (pc->options.audio_codec == MEDIA_CODEC_PCMA) {

        sdp_append_pcma(&pc->local_sdp);
        sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
        if (pc->role == DTLS_SRTP_ROLE_SERVER) {
            sdp_append(&pc->local_sdp, "a=setup:actpass");
        } else {
            sdp_append(&pc->local_sdp, "a=setup:active");
        }
        strcat(pc->local_sdp.content, description);
    }

    JLOG_INFO("%s local description:\n%s\n", pc->name, pc->local_sdp.content);
    mqtt_answer_publish(pc->local_sdp.content);
    pc->b_offer_created = 1;

    if (pc->cb_candidate) {
        pc->cb_candidate(pc->local_sdp.content, pc->user_data);
    }

    packet_fifo_reset(&pc->dtls_fifo);
    packet_fifo_reset(&pc->other_fifo);
    packet_fifo_reset(&pc->rtp_fifo);

    rtp_list_init(&pc->rtp_send_list);
    rtp_list_init(&pc->rtp_cache_list);

    STATE_CHANGED(pc, PEER_CONNECTION_INIT);
}

void *loop_thread_entry(void *param) {

//   memset(pc->juice_agent_buf, 0, sizeof(pc->juice_agent_buf));
//   pc->juice_agent_ret = -1;
    int ret;
    peer_connection_t *pc = (peer_connection_t *)param;

    thread_set_name_self(pc->name);

    while(1) {
        switch (pc->state) {
            case PEER_CONNECTION_START: {
                peer_connection_state_start(pc);
                // if (!pc->b_offer_created) {
                //   peer_connection_state_new(pc);
                // }
                break;
            }
            case PEER_CONNECTION_CONNECTING: {
                JLOG_INFO("PEER_CONNECTION_CONNECTING");
                if (agent_get_selected_candidate_pair(pc->juice_agent, &pc->local_cand, &pc->remote_cand) == 0) {
                    char address[JUICE_MAX_ADDRESS_STRING_LEN];
                    memset(address, 0, JUICE_MAX_ADDRESS_STRING_LEN);
                    addr_record_to_string(&pc->local_cand.resolved, address, JUICE_MAX_ADDRESS_STRING_LEN);
                    JLOG_INFO("%s local address: %s\n", pc->name, address);
                    addr_record_to_string(&pc->remote_cand.resolved, address, JUICE_MAX_ADDRESS_STRING_LEN);
                    JLOG_INFO("%s remote address: %s\n", pc->name, address);
                    STATE_CHANGED(pc, PEER_CONNECTION_HANDSHAKE);
                } else {
                    //no avail
                    JLOG_INFO("no selected pair");
                }
                break;
            }
            case PEER_CONNECTION_HANDSHAKE:
            if (pc->dtls_srtp.state == DTLS_SRTP_STATE_INIT) {
                //juice_suspend(pc->juice_agent);
                JLOG_INFO("DTLS-SRTP %s handshake start", pc->dtls_srtp.role == DTLS_SRTP_ROLE_SERVER ? "server" : "client");
                if (dtls_srtp_handshake(&pc->dtls_srtp, &pc->remote_cand.resolved) == 0) {

                JLOG_INFO("DTLS-SRTP %s handshake done", pc->dtls_srtp.role == DTLS_SRTP_ROLE_SERVER ? "server" : "client");
        #ifdef HAVE_GST
                if (pc->audio_stream) {
                    media_stream_play(pc->audio_stream);
                }

                if (pc->video_stream) {
                    media_stream_play(pc->video_stream);
                }
        #endif

                  if (pc->options.datachannel) {
                    JLOG_INFO("SCTP create socket");
                //     pc->sctp.data_rb = pc->data_rb;
                    sctp_create_socket(&pc->sctp, &pc->dtls_srtp);
                  }

                }
            } else if (pc->dtls_srtp.state == DTLS_SRTP_STATE_CONNECTED) {
                    //juice_resume(pc->juice_agent);
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
                    peer_connection_rtp_process_thread_init(pc, rtp_process_thread_entry);
                    STATE_CHANGED(pc, PEER_CONNECTION_COMPLETED);
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
            case PEER_CONNECTION_COMPLETED: {
                //recv fifo
                char buf[4096];
                int recv_count;
                recv_count = dtls_srtp_read(&pc->dtls_srtp, buf, 4096);
                if (recv_count > 0) {
                    sctp_incoming_data(&pc->sctp, buf, recv_count);
                }
                break;
            }
            case PEER_CONNECTION_FAILED:
            break;
            case PEER_CONNECTION_DISCONNECTED:
            break;
            case PEER_CONNECTION_CLOSED:
            break;
            default:
            break;
        }
        usleep(1*1000);
    }
    pthread_exit(&ret);
    return NULL;
}

void peer_connection_reset_video_fifo(peer_connection_t *pc) {
    packet_fifo_reset(&pc->video_fifo);
}

void peer_connection_init(peer_connection_t *pc) {

//   uint32_t ssrc;
//   RtpPayloadType type;

    // recv fifo
    packet_fifo_init(&pc->rtp_fifo, 64);
    packet_fifo_init(&pc->dtls_fifo, 64);
    packet_fifo_init(&pc->other_fifo, 64);
    // send fifo
    packet_fifo_init(&pc->video_fifo, 512);
    packet_fifo_init(&pc->audio_fifo, 256);
    packet_fifo_init(&pc->data_fifo, 256);
    //   memset(&pc->sctp, 0, sizeof(pc->sctp));
    if (pc->role == DTLS_SRTP_ROLE_SERVER) {
        pc->recv_timeout = 1000*10;
    } else {
        pc->recv_timeout = 1000;
    }
    pc->juice_agent = juice_create(&pc->options.juice_config);
    dtls_srtp_ssl_dbg_init(&pc->dtls_srtp, 1, 0);
    dtls_srtp_init(&pc->dtls_srtp, pc->role, pc);
    pc->dtls_srtp.udp_recv = (mbedtls_ssl_recv_t *)peer_connection_dtls_recv;
    pc->dtls_srtp.udp_send = (mbedtls_ssl_send_t *)peer_connection_dtls_send;
    // pc->loop_thread_entry = peer_connection_loop_thread_entry;
    // pc->loop_thread_entry = rtp_frame_process_thread_entry;

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

    if (pc->options.video_codec) {
    #ifdef HAVE_GST
        pc->video_stream = media_stream_create(pc->options.video_codec,
        pc->options.video_outgoing_pipeline, pc->options.video_incoming_pipeline);
        pc->video_stream->outgoing_rb = pc->video_rb;
    #else
        rtp_packetizer_init(&pc->video_packetizer, pc->options.video_codec,
        peer_connection_set_cb_rtp_packet, pc);
    #endif
    }

    peer_connection_loop_thread_init(pc, loop_thread_entry);
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
    int ret = -1; 
    if (pc->dtls_srtp.state == DTLS_SRTP_STATE_CONNECTED) {
        ret = rtp_packetizer_encode(&pc->video_packetizer, (uint8_t*)buf, len);
    } else {
        JLOG_ERROR("dtls srtp not connected");
    }
    return ret;
}

int peer_connection_datachannel_send(peer_connection_t *pc, uint16_t si, char *message,size_t len) {

    if(!sctp_is_connected(&pc->sctp)) {
        JLOG_ERROR("sctp not connected");
        return -1;
    }
    return sctp_outgoing_data(&pc->sctp, message, len, si, PPID_STRING);
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
/*
void peer_connection_send_rtp_packet(peer_connection_t *pc, char *packet, int bytes) {
    dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, (char *)packet, &bytes);
    rtp_header_t *rtp_header = (rtp_header_t *)packet;
    int seq_number = ntohs(rtp_header->seq_number);
    // JLOG_INFO("add rtp frame[%d]", seq_number);
    rtp_frame_add(&pc->rtp_cache_list, seq_number, packet, bytes);
    // int ret = juice_send(pc->juice_agent, packet, bytes);
    // if (ret == JUICE_ERR_SUCCESS) {
    //     return bytes;
    // } else {
    //     return -1;
    // }
}
*/
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

void peer_connection_set_datachannel_cb(peer_connection_t *pc, void *userdata,
    void (*on_messasge)(char *msg, size_t len, uint16_t si, void *userdata),
    void (*on_open)(void *userdata),
    void (*on_close)(void *userdata)) {

    if (pc) {
        sctp_onopen(&pc->sctp, on_open);
        sctp_onclose(&pc->sctp, on_close);
        sctp_onmessage(&pc->sctp, on_messasge);
        sctp_set_userdata(&pc->sctp, userdata);
    }
}

void peer_connection_set_current_ip(const char *ip) {

  // ports_set_current_ip(ip);
}
