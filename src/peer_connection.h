/**
 * @file peer_connection.h
 * @brief Struct peer_connection_t
 */
#ifndef PEER_CONNECTION_H_
#define PEER_CONNECTION_H_

#ifdef __cplusplus
extern "C" {
#endif

// #include "sctp.h"
#include "juice.h"
#include "agent.h"
#include "dtls_srtp.h"
#include "rtc_fifo.h"
// #include "sdp.h"
// #include "codec.h"
// #include "config.h"
// #include "rtp.h"
// #include "rtcp_packet.h"

typedef enum peer_connection_state {
  PEER_CONNECTION_INIT = 0,
  PEER_CONNECTION_NEW,
  PEER_CONNECTION_CONNECTING,
  PEER_CONNECTION_CONNECTED,
  PEER_CONNECTION_COMPLETED,
  PEER_CONNECTION_FAILED,
  PEER_CONNECTION_DISCONNECTED,
  PEER_CONNECTION_CLOSED,

} peer_connection_state_t;

typedef struct peer_options {
	juice_config_t juice_config;
  // MediaCodec audio_codec;
  // MediaCodec video_codec;
  int data_channel;
  
#ifdef HAVE_GST
  const char *audio_outgoing_pipeline;
  const char *audio_incoming_pipeline;
  const char *video_outgoing_pipeline;
  const char *video_incoming_pipeline;
#endif

} peer_options_t;

typedef struct peer_connect {
  char *name;
  peer_options_t options;
  peer_connection_state_t state;
  juice_agent_t juice_agent;
  juice_state_t juice_state;
	ice_candidate_t local_cand, remote_cand;
  dtls_srtp_t dtls_srtp;
  // Sctp sctp;

  char local_sdp[JUICE_MAX_SDP_STRING_LEN];
  char remote_sdp[JUICE_MAX_SDP_STRING_LEN];

  void (*onicecandidate)(char *sdp, void *user_data);
  void (*oniceconnectionstatechange)(peer_connection_state_t state, void *user_data);
  void (*ontrack)(uint8_t *packet, size_t bytes, void *user_data);
  void (*on_connected)(void *userdata);
  void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void *user_data);

  void *user_data;

  // uint8_t temp_buf[CONFIG_MTU];
  rtc_fifo_t recv_fifo;
  // uint8_t agent_buf[CONFIG_MTU];
  // int agent_ret;
  // int b_offer_created;

  // Buffer *audio_rb[2];
  // Buffer *video_rb[2];
  // Buffer *data_rb[2];
  void (*loop)(void *param);

#ifdef HAVE_GST
  MediaStream *audio_stream;
  MediaStream *video_stream;
#else
  // RtpPacketizer audio_packetizer;
  // RtpPacketizer video_packetizer;
#endif

} peer_connection_t;

void peer_connection_configure(peer_connection_t *pc, char *name, peer_options_t *options);

void peer_connection_init(peer_connection_t *pc);

void peer_connection_set_remote_description(peer_connection_t *pc, const char *sdp);

void peer_connection_create_offer(peer_connection_t *pc);

/**
 * @brief register callback function to handle packet loss from RTCP receiver report
 * @param[in] peer connection
 * @param[in] callback function void (*cb)(float fraction_loss, uint32_t total_loss, void *userdata)
 * @param[in] userdata for callback function
 */
void peer_connection_on_receiver_packet_loss(peer_connection_t *pc,
 void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void *userdata));

/**
 * @brief register callback function to handle event when the connection is established
 * @param[in] peer connection
 * @param[in] callback function void (*cb)(void *userdata)
 * @param[in] userdata for callback function
 */
void peer_connection_on_connected(peer_connection_t *pc, void (*on_connected)(void *userdata));
/**
 * @brief Set the callback function to handle onicecandidate event.
 * @param A peer_connection_t.
 * @param A callback function to handle onicecandidate event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_onicecandidate(peer_connection_t *pc, void (*onicecandidate)(char *sdp_text, void *userdata));

/**
 * @brief Set the callback function to handle oniceconnectionstatechange event.
 * @param A peer_connection_t.
 * @param A callback function to handle oniceconnectionstatechange event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_oniceconnectionstatechange(peer_connection_t *pc,
 void (*oniceconnectionstatechange)(peer_connection_state_t state, void *userdata));

/**
 * @brief Set the callback function to handle ontrack event.
 * @param A peer_connection_t.
 * @param A callback function to handle ontrack event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_ontrack(peer_connection_t *pc, void (*ontrack)(uint8_t *packet, size_t bytes, void *userdata));


/**
 * @brief register callback function to handle event of datachannel
 * @param[in] peer connection
 * @param[in] callback function when message received
 * @param[in] callback function when connection is opened
 * @param[in] callback function when connection is closed
 */
void peer_connection_ondatachannel(peer_connection_t *pc,
 void (*onmessasge)(char *msg, size_t len, void *userdata),
 void (*onopen)(void *userdata),
 void (*onclose)(void *userdata));

/**
 * @brief send message to data channel
 * @param[in] peer connection
 * @param[in] message buffer
 * @param[in] length of message
 */
int peer_connection_datachannel_send(peer_connection_t *pc, char *message, size_t len);
int peer_connection_datachannel_send_binary(peer_connection_t *pc, char *message, size_t len);

int peer_connection_send_rtp_packet(peer_connection_t *pc, uint8_t *packet, int bytes);

void peer_connection_set_host_address(peer_connection_t *pc, const char *host);

int peer_connection_send_audio(peer_connection_t *pc, const uint8_t *packet, size_t bytes);

int peer_connection_send_video(peer_connection_t *pc, const uint8_t *packet, size_t bytes);

void peer_connection_set_current_ip(const char *ip);

void peer_options_set_default(peer_options_t *options, int port_begin, int port_end);

#ifdef __cplusplus
}
#endif

#endif // PEER_CONNECTION_H_
