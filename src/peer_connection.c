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
#include "rtp_enc.h"

// #define STATE_CHANGED(pc, curr_state) if(pc->cb_state_change && pc->state != curr_state) { pc->cb_state_change(curr_state, pc->user_data); pc->state = curr_state; }


#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define bits_mask(i) (1 << (i))

// Turn server config
static juice_turn_server_t turn_server;

int peer_connection_send_rtp_frame(peer_connection_t *pc, int ssrc, int seq) {
    int ret = JUICE_ERR_FAILED;
    static int _ssrc = 0;
    static int _seq = 0;

    static rtp_frame_key_t notfound_key = {0, 0};

    if (ssrc != _ssrc || seq != _seq) { // 连续发送同一个包只处理一次
        _ssrc = ssrc;
        _seq = seq;

        if (notfound_key.ssrc != ssrc || notfound_key.seq != seq) { // 连续同一个包未找到只处理一次

            rtp_frame_key_t key;
            key.ssrc = ssrc;
            key.seq = seq;

            if (rtp_list_rlock(&pc->rtp_tx_cache_list) == 0) {
                rtp_frame_t *frame = rtp_list_find_by_key(&pc->rtp_tx_cache_list, key);
                if (frame) {
                    if (rtp_list_wlock(&pc->rtp_rtx_cache_list) == 0) {
                        ret = rtp_list_insert_packet(&pc->rtp_rtx_cache_list, frame->packet, frame->bytes);
                        if (ret < 0) {
                            JLOG_ERROR("rtp_list_insert_packet error, count:%d", rtp_list_count(&pc->rtp_rtx_cache_list));
                        }
                        rtp_list_unlock(&pc->rtp_rtx_cache_list);
                    }
                    JLOG_INFO("rtx packet ssrc: %d seq: %d, length: %d", ssrc, seq,  frame->bytes);
                    // rtx
                    // rtp_packetizer_encode(&pc->video_rtx_packetizer, frame->packet, frame->bytes);
                    // ret = peer_connection_encrypt_send(pc, frame->packet, frame->bytes);
                } else {
                    JLOG_ERROR("rtx key[%d:%d] is not found!", key.ssrc, key.seq);
                    // rtp_list_print_all(&pc->rtp_tx_cache_list, 0);
                    notfound_key = key;
                }
                rtp_list_unlock(&pc->rtp_tx_cache_list);
            }
        }
    }

    return ret;
}

void peer_connection_rtp_frame_lost_process(peer_connection_t *pc, int ssrc, int seq, uint16_t lostmap) {
    if (lostmap) {
        for (int i = 15; i >= 0; i--) {
            if (lostmap & bits_mask(i)) {
                // pid_array[i+1] = pid++;
                if (peer_connection_send_rtp_frame(pc, ssrc, seq + i + 1) < 0)
                    return; // return for not found
            }
        }
    }
    peer_connection_send_rtp_frame(pc, ssrc, seq);
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
                case RTCP_SDES: {
                    // 源描述（Source Description）
                    break;
                }
                case RTCP_SR: {
                    // 发送端报告（Sender Report）
                    break;
                }
                case RTCP_RR: {
                    // 接收端报告（Receiver Report）
                    if(rtcp_header.rc > 0) {
                        rtcp_rr_t *rtcp_rr = (rtcp_rr_t *)rtcp_buf;
                        uint32_t ssrc = ntohl(rtcp_rr->ssrc);

                        uint32_t block_size = (ntohs(rtcp_rr->header.length) - 1) / sizeof(rtcp_report_block_t) / sizeof(uint32_t);
                        block_size = block_size > REPORT_BLOCK_SIZE ? REPORT_BLOCK_SIZE : block_size; // limit block size;

                        for (int i = 0; i < block_size; i++) {
                            uint32_t fraction = ntohl(rtcp_rr->report_block[i].flcnpl) >> 24;
                            uint32_t total = ntohl(rtcp_rr->report_block[i].flcnpl) & 0x00FFFFFF;
                            uint32_t rsrc = ntohl(rtcp_rr->report_block[i].rsrc);
                            if(pc->cb_receiver_packet_loss && fraction > 0) {
                                pc->cb_receiver_packet_loss(rsrc, (float)fraction/256.0, total, pc);
                            }
                        }
                    }
                    break;
                }
                case RTCP_RTPFB: {
                    switch (rtcp_header.rc) {
                        case RTCP_FMT_RTPFB_NACK: {
                            rtcp_rtpfb_nack_t rtpfb_nack = rtcp_packet_parse_rtpfb_nack(rtcp_buf);
                            uint32_t nack_block_size = ntohs(rtpfb_nack.header.length) - 2;
                            nack_block_size = nack_block_size > NACK_BLOCK_SIZE ? NACK_BLOCK_SIZE : nack_block_size; // limit block size;
                            uint32_t ssrc_ps = ntohl(rtpfb_nack.ssrc_ps);
                            uint32_t ssrc_ms = ntohl(rtpfb_nack.ssrc_ms);
                            // JLOG_INFO_DUMP_HEX(rtcp_buf, rtcp_len,"RTCP_FMT_RTPFB_NACK->ssrc_ps:%d, ssrc_ms:%d", ssrc_ps, ssrc_ms);
                            for (int i = 0; i < nack_block_size; i++) {
                                uint16_t pid = ntohs(rtpfb_nack.nack_block[i].pid);
                                uint16_t lostmap = ntohs(rtpfb_nack.nack_block[i].lostmap);
                                // JLOG_INFO("pid:%d, lostmap:%04X, ssrc_ps:%d, ssrc_ms:%d", pid, lostmap, ssrc_ps, ssrc_ms);
                                peer_connection_rtp_frame_lost_process(pc, ssrc_ms, pid, lostmap);
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
                            if (ssrc_ms == RTP_SSRC_TYPE_H264 && rtcp_psfb_pli_process() == 0) {
                                JLOG_WARN("PSFB_PLI ssrc_ps:%d, ssrc_ms:%d", ssrc_ps, ssrc_ms);
                            }
                            break;
                        }
                        case RTCP_FMT_PSFB_REMB: {
                            rtcp_psfb_remb_t *psfb_remb = (rtcp_psfb_remb_t *)rtcp_buf;
                            uint32_t ssrc_ps = ntohl(psfb_remb->ssrc_ps);
                            uint32_t ssrc_ms = ntohl(psfb_remb->ssrc_ms);
                            uint32_t remb = ntohl(psfb_remb->remb);
                            uint32_t rb = ntohl(psfb_remb->br);
                            uint32_t ssrc_feedback_block_size = ntohs(psfb_remb->header.length) - 4;
                            ssrc_feedback_block_size = ssrc_feedback_block_size > SSRC_FEEDBACK_BLOCK_SIZE ? SSRC_FEEDBACK_BLOCK_SIZE : ssrc_feedback_block_size; // limit block size;
                            rtcp_psfb_remb_br_t *ptr_br = (rtcp_psfb_remb_br_t *)&rb;
                            uint32_t num_ssrc = ptr_br->num_ssrc;
                            uint32_t exp = ptr_br->exp;
                            uint32_t mantissa = ptr_br->mantissa;
                            JLOG_DEBUG("PSFB_REMB: ssrc_ps:%d, ssrc_ms:%d, remb:%08X, num_ssrc:%d, br: %fkBps",
                                        ssrc_ps, ssrc_ms, remb, num_ssrc, pow(2, exp) * mantissa / 1000);
                            for (int i = 0; i < ssrc_feedback_block_size; i++) {
                                JLOG_DEBUG("ssrc_feedback: %d", ntohl(psfb_remb->ssrc_feedback_block[i]));
                            }
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
                    //JLOG_ERROR_DUMP_HEX(rtcp_buf, rtcp_len, "--------------unknow rtcp type[%d] parse, rtcp_buf[%d]-----------", rtcp_header.type, rtcp_len);
                    break;
                }
            }
            offset += rtcp_len;
        } else {
            break;
        }
    }
}

static void *rtp_push_thread_entry(void *args)
{
    int ret = 0;
    rtp_frame_t *frame;
    rtp_frame_t *tmp;
    peer_connection_t *pc = args;

    thread_set_name_self("rtp_push");

    while (1) {
        if (rtp_list_wlock(&pc->rtp_tx_cache_list) == 0) {
            HASH_ITER(hh, pc->rtp_tx_cache_list.utlist, frame, tmp) {
                if (frame->timeout_count-- <= 0) {
                    rtp_list_delete(&pc->rtp_tx_cache_list, frame);
                }
            }
            rtp_list_unlock(&pc->rtp_tx_cache_list);
        }
        usleep(RTP_FRAME_COUNT_INTERVAL*1000);
    }
    pthread_exit(&ret);
    return NULL;
}

int peer_connection_rtp_push_thread_init(peer_connection_t *pc, void *(*thread_entry)(void *)) {
    int ret = -1;
    thread_attr_t attr;

    if (pc->rtp_push_thread == NULL) {
        thread_attr_init(&attr, pc->rtp_push_thread_prio, pc->rtp_push_thread_ssize);
        ret = thread_init_ex(&pc->rtp_push_thread, &attr, thread_entry, pc);
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

int peer_connection_dtls_recv(void *ctx, char *buf, size_t len) {
    int ret = 0;
    int recv_count = 0;
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *) ctx;
    peer_connection_t *pc = (peer_connection_t *) dtls_srtp->user_data;
    uint32_t timeout_count = TIMEOUT_COUNT(pc->recv_timeout, PER_TIMEOUT);

    while (timeout_count > 0 && recv_count < len) {
        ret = packet_fifo_read(&pc->dtls_fifo, buf + recv_count, len - recv_count);
        if (ret > 0) {
            recv_count += ret;
        } else {
            // no data
            usleep(1000 * PER_TIMEOUT);
            timeout_count--;
        }
    }
    if (recv_count > 0) {
        return recv_count;
    } else {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
}

int peer_connection_dtls_send(void *ctx, const char *buf, size_t len) {
    int ret;
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *)ctx;
    peer_connection_t *pc = (peer_connection_t *) dtls_srtp->user_data;

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
    if (strstr(sdp, "srflx") || strstr(sdp, "host"))
        return;
    // if (strstr(sdp, "host"))
    //     return;
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
}

static void rtp_recv_packet_process(peer_connection_t *pc, char *packet, int bytes) {
    int ret;
    // JLOG_INFO( "%s recv rtp: %ld", pc->name, size);
    if (rtcp_packet_validate((uint8_t *)packet, bytes)) {
        ret = dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, packet, &bytes);
        if (ret == srtp_err_status_ok) {
            // JLOG_INFO_DUMP_HEX(packet, bytes, "rtcp packet[%d]:", bytes);
            peer_connection_incoming_rtcp(pc, (uint8_t *)packet, bytes);
        } else {
            JLOG_INFO_DUMP_HEX(packet, bytes, "--------------invalid[%d] rtcp packet[%d]---------------", ret, bytes);
        }
    } else {
        ret = dtls_srtp_decrypt_rtp_packet(&pc->dtls_srtp, packet, &bytes);
        if (ret == srtp_err_status_ok) {
            if (rtp_list_wlock(&pc->rtp_recv_cache_list) == 0) {
                ret = rtp_list_insert_packet(&pc->rtp_recv_cache_list, packet, bytes);
                if (ret < 0) {
                    // JLOG_ERROR("rtp_list_insert_packet error, count:%d", rtp_list_count(&pc->rtp_recv_cache_list));
                }
                rtp_list_unlock(&pc->rtp_recv_cache_list);
            }
        } else {
            JLOG_INFO_DUMP_HEX(packet, bytes, "--------------invalid[%d] rtp packet[%d]---------------", ret, bytes);
        }
    }
}

// Agent on message received
static void agent_on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    int ret;
    peer_connection_t *pc = user_ptr;
    if((data[0]>=128) && (data[0]<=191)) {
        rtp_recv_packet_process(pc, (char *)data, size);
        return;
    }
    if((data[0]>=20)  && (data[0]<=64)) {
        // JLOG_INFO( "%s recv dtls: %ld", pc->name, size);
        packet_fifo_write(&pc->dtls_fifo, (char *)data, size);
        return;
    }

    JLOG_INFO( "%s recv other: %ld", pc->name, size);
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
    pc->options.audio_codec = PEER_CONNECTION_AUDIO_CODEC;
    pc->options.video_codec = PEER_CONNECTION_VIDEO_CODEC;
    pc->options.video_rtx_codec = PEER_CONNECTION_VIDEO_RTX_CODEC;
    pc->options.datachannel = PEER_CONNECTION_DATA_CHANNEL;

    // pc loop
    pc->loop_thread = NULL;
    pc->loop_thread_ssize = 64*1024;
    pc->loop_thread_prio = THREAD_DEFAULT_PRIORITY - 1;

    // rtp push
    pc->rtp_push_thread = NULL;
    pc->rtp_push_thread_ssize = 32*1024;
    pc->rtp_push_thread_prio = THREAD_DEFAULT_PRIORITY - 2;

    // rtp video encode
    pc->rtp_video_enc_thread = NULL;
    pc->rtp_video_enc_loop_flag = 0;
    pc->rtp_video_enc_thread_ssize = 32*1024;
    pc->rtp_video_enc_thread_prio = THREAD_DEFAULT_PRIORITY - 2;

    // rtp audio encode
    pc->rtp_audio_enc_thread = NULL;
    pc->rtp_audio_enc_loop_flag = 0;
    pc->rtp_audio_enc_thread_ssize = 32*1024;
    pc->rtp_audio_enc_thread_prio = THREAD_DEFAULT_PRIORITY - 2;

    // rtp audio decode
    pc->rtp_audio_dec_thread = NULL;
    pc->rtp_audio_dec_loop_flag = 0;
    pc->rtp_audio_dec_thread_ssize = 32*1024;
    pc->rtp_audio_dec_thread_prio = THREAD_DEFAULT_PRIORITY - 2;
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

    JLOG_INFO("%s local description:\n%s\n", pc->name, pc->local_sdp.content);
    mqtt_answer_publish(pc->local_sdp.content);
    pc->b_offer_created = 1;

    if (pc->cb_candidate) {
        pc->cb_candidate(pc->local_sdp.content, pc->user_data);
    }

    packet_fifo_reset(&pc->dtls_fifo);

    rtp_list_init(&pc->rtp_rtx_cache_list);
    rtp_list_init(&pc->rtp_tx_cache_list);
    rtp_list_init(&pc->rtp_recv_cache_list);

    STATE_CHANGED(pc, PEER_CONNECTION_INIT);
}

void *loop_thread_entry(void *param) {

//   memset(pc->juice_agent_buf, 0, sizeof(pc->juice_agent_buf));
//   pc->juice_agent_ret = -1;
    int ret;
    rtp_frame_t *frame;
    rtp_frame_t *tmp;
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
            case PEER_CONNECTION_HANDSHAKE: {
                if (pc->dtls_srtp.state == DTLS_SRTP_STATE_INIT) {
                    //juice_suspend(pc->juice_agent);
                    JLOG_INFO("DTLS-SRTP %s handshake start", pc->dtls_srtp.role == DTLS_SRTP_ROLE_SERVER ? "server" : "client");
                    if (dtls_srtp_handshake(&pc->dtls_srtp, &pc->remote_cand.resolved) == 0) {
                        JLOG_INFO("DTLS-SRTP %s handshake done", pc->dtls_srtp.role == DTLS_SRTP_ROLE_SERVER ? "server" : "client");
                        if (pc->options.datachannel) {
                            JLOG_INFO("SCTP create socket");
                            sctp_create_socket(&pc->sctp, &pc->dtls_srtp);
                        }
                    }
                } else if (pc->dtls_srtp.state == DTLS_SRTP_STATE_CONNECTED) {
                    peer_connection_rtp_push_thread_init(pc, rtp_push_thread_entry);
                    STATE_CHANGED(pc, PEER_CONNECTION_COMPLETED);
                    rtp_enc_init(pc);
                    rtp_enc_start(pc);
                    rtp_dec_init(pc);
                }
                break;
            }
            case PEER_CONNECTION_COMPLETED: {
                if (rtp_list_count(&pc->rtp_rtx_cache_list) > 0) {
                    if (rtp_list_wlock(&pc->rtp_rtx_cache_list) == 0) {
                        HASH_ITER(hh, pc->rtp_rtx_cache_list.utlist, frame, tmp) {
                            // process rtp packet
                            peer_connection_encrypt_send(pc, frame->packet, frame->bytes);
                            // remove frame
                            rtp_list_delete(&pc->rtp_rtx_cache_list, frame);
                        }
                        rtp_list_unlock(&pc->rtp_rtx_cache_list);
                    }
                }
                // if (pc->options.datachannel) {
                //     //recv fifo
                //     char buf[4096];
                //     int recv_count;
                //     recv_count = dtls_srtp_read(&pc->dtls_srtp, buf, 4096);
                //     if (recv_count > 0) {
                //         sctp_incoming_data(&pc->sctp, buf, recv_count);
                //     }
                // }
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

// void peer_connection_reset_video_fifo(peer_connection_t *pc) {
//     packet_fifo_reset(&pc->video_fifo);
// }

void peer_connection_init(peer_connection_t *pc) {

//   uint32_t ssrc;
//   RtpPayloadType type;

    // recv fifo
    packet_fifo_init(&pc->dtls_fifo, 64);

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

int peer_connection_encrypt_send(peer_connection_t *pc, char *packet, int bytes) {
    int ret = JUICE_ERR_FAILED;

    ret = dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, (char *)packet, &bytes);
    if (ret == srtp_err_status_ok) {
        ret = juice_send(pc->juice_agent, packet, bytes);
    } else {
        JLOG_ERROR("dtls_srtp_encrypt_rtp_packet %d error: %d", bytes, ret);
    }
    return ret;
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
    rtp_frame_add(&pc->rtp_tx_cache_list, seq_number, packet, bytes);
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
 void (*on_receiver_packet_loss)(uint32_t ssrc, float fraction_loss, uint32_t total_loss, void *userdata)) {

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
