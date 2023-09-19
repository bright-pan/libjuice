/**
 * @file peer_connection.h
 * @brief Struct peer_connection_t
 */
#ifndef PEER_CONNECTION_H_
#define PEER_CONNECTION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "sctp.h"
#include "juice.h"
#include "agent.h"
#include "dtls_srtp.h"
#include "packet.h"
#include "sdp.h"
#include "codec.h"
// #include "config.h"
#include "rtp.h"
#include "rtp_list.h"
// #include "rtcp_packet.h"


#define STATE_CHANGED(pc, curr_state) if(pc->cb_state_change && pc->state != curr_state) { pc->cb_state_change(curr_state, pc); pc->state = curr_state; }


typedef enum peer_connection_state {
    PEER_CONNECTION_INIT = 0,
    PEER_CONNECTION_START,
    PEER_CONNECTION_CONNECTING,
    PEER_CONNECTION_HANDSHAKE,
    PEER_CONNECTION_COMPLETED,
    PEER_CONNECTION_FAILED,
    PEER_CONNECTION_DISCONNECTED,
    PEER_CONNECTION_CLOSED,
} peer_connection_state_t;

typedef struct peer_options {
	juice_config_t juice_config;
    media_codec_t audio_codec;
    media_codec_t video_codec;
    media_codec_t video_rtx_codec;
    int datachannel;
} peer_options_t;

typedef struct peer_connect {
    char *name;
    uint32_t stack_size; //loop 线程堆栈大小
    uint32_t recv_timeout; // 接收等待时间
    dtls_srtp_role_t role;
    peer_options_t options;
    peer_connection_state_t state;
    juice_agent_t *juice_agent;
    juice_state_t juice_state;
	ice_candidate_t local_cand, remote_cand;
    dtls_srtp_t dtls_srtp;
    sctp_t sctp;

    sdp_t local_sdp;
    sdp_t remote_sdp;
    // char description[SDP_CONTENT_LENGTH];

    void (*cb_candidate)(char *sdp, void *user_data);
    void (*cb_state_change)(peer_connection_state_t state, void *user_data);
    void (*cb_track)(uint8_t *packet, size_t bytes, void *user_data);
    void (*cb_connected)(void *userdata);
    void (*cb_receiver_packet_loss)(uint32_t ssrc, float fraction_loss, uint32_t total_loss, void *user_data);

    void *user_data;

    // uint8_t temp_buf[CONFIG_MTU];
    packet_fifo_t dtls_fifo; //recv dtls
    // packet_fifo_t rtp_fifo; //recv rtp
    // packet_fifo_t other_fifo; // recv other
    // uint8_t agent_buf[CONFIG_MTU];
    // int agent_ret;
    int b_offer_created;

    // packet_fifo_t audio_fifo; //send audio
    // packet_fifo_t video_fifo; //send video
    // packet_fifo_t data_fifo; //send data

    rtp_list_t rtp_tx_cache_list; // has been sended frame cache list
    rtp_list_t rtp_recv_cache_list; // has been sended frame cache list
    rtp_list_t rtp_rtx_cache_list; // has been sended frame cache list

    thread_t loop_thread; // thread handle
    int loop_thread_ssize; // stack size
    int loop_thread_prio; // sche proirity

    thread_t rtp_push_thread; // thread handle
    int rtp_push_thread_ssize; // stack size
    int rtp_push_thread_prio; // sche proirity

    thread_t rtp_video_enc_thread; // thread handle
    int rtp_video_enc_loop_flag;
    int rtp_video_enc_thread_ssize; // stack size
    int rtp_video_enc_thread_prio; // sche proirity

    thread_t rtp_audio_enc_thread; // thread handle
    int rtp_audio_enc_loop_flag;
    int rtp_audio_enc_thread_ssize; // stack size
    int rtp_audio_enc_thread_prio; // sche proirity

    thread_t rtp_audio_dec_thread; // thread handle
    int rtp_audio_dec_loop_flag;
    int rtp_audio_dec_thread_ssize; // stack size
    int rtp_audio_dec_thread_prio; // sche proirity

    rtp_packetizer_t audio_packetizer;
    rtp_packetizer_t video_packetizer;
    rtp_packetizer_t video_rtx_packetizer;

} peer_connection_t;

void peer_connection_configure(peer_connection_t *pc, char *name, dtls_srtp_role_t role, peer_options_t *options);

void peer_connection_init(peer_connection_t *pc);

void peer_connection_set_remote_description(peer_connection_t *pc, const char *sdp);
void peer_connection_add_remote_candidate(peer_connection_t *pc, const char *sdp);
void peer_connection_start(peer_connection_t *pc);

int peer_connection_dtls_recv(void *ctx, char *buf, size_t len);
int peer_connection_dtls_send(void *ctx, const char *buf, size_t len);

/**
 * @brief register callback function to handle packet loss from RTCP receiver report
 * @param[in] peer connection
 * @param[in] callback function void (*cb)(float fraction_loss, uint32_t total_loss, void *userdata)
 * @param[in] userdata for callback function
 */
void peer_connection_set_cb_receiver_packet_loss(peer_connection_t *pc,
 void (*on_receiver_packet_loss)(uint32_t ssrc, float fraction_loss, uint32_t total_loss, void *userdata));

/**
 * @brief register callback function to handle event when the connection is established
 * @param[in] peer connection
 * @param[in] callback function void (*cb)(void *userdata)
 * @param[in] userdata for callback function
 */
void peer_connection_set_cb_connected(peer_connection_t *pc, void (*on_connected)(void *userdata));
/**
 * @brief Set the callback function to handle onicecandidate event.
 * @param A peer_connection_t.
 * @param A callback function to handle onicecandidate event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_set_cb_candidate(peer_connection_t *pc, void (*on_candidate)(char *sdp_text, void *userdata));
/**
 * @brief Set the callback function to handle oniceconnectionstatechange event.
 * @param A peer_connection_t.
 * @param A callback function to handle oniceconnectionstatechange event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_set_cb_state_change(peer_connection_t *pc, void (*on_state_change)(peer_connection_state_t state, void *userdata));
/**
 * @brief Set the callback function to handle ontrack event.
 * @param A peer_connection_t.
 * @param A callback function to handle ontrack event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_set_cb_track(peer_connection_t *pc, void (*on_track)(uint8_t *packet, size_t bytes, void *userdata));


/**
 * @brief register callback function to handle event of datachannel
 * @param[in] peer connection
 * @param[in] callback function when message received
 * @param[in] callback function when connection is opened
 * @param[in] callback function when connection is closed
 */
void peer_connection_set_datachannel_cb(peer_connection_t *pc, void *userdata,
 void (*on_messasge)(char *msg, size_t len, uint16_t si, void *userdata),
 void (*on_open)(void *userdata),
 void (*on_close)(void *userdata));

/**
 * @brief send message to data channel
 * @param[in] peer connection
 * @param[in] message buffer
 * @param[in] length of message
 */
int peer_connection_datachannel_send(peer_connection_t *pc, uint16_t si, char *message, size_t len);
int peer_connection_datachannel_send_binary(peer_connection_t *pc, char *message, size_t len);

int peer_connection_send_rtp_packet(peer_connection_t *pc, char *packet, int bytes);

void peer_connection_set_host_address(peer_connection_t *pc, const char *host);

int peer_connection_send_audio(peer_connection_t *pc, const uint8_t *packet, size_t bytes);

int peer_connection_send_video(peer_connection_t *pc, const uint8_t *packet, size_t bytes);

void peer_connection_set_current_ip(const char *ip);

void peer_options_set_default(peer_options_t *options, int port_begin, int port_end);
int peer_connection_encrypt_send(peer_connection_t *pc, char *packet, int bytes);

// void peer_connection_reset_video_fifo(peer_connection_t *pc);
#ifdef __cplusplus
}
#endif

#endif // PEER_CONNECTION_H_
