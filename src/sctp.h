#ifndef SCTP_H_
#define SCTP_H_

#include "config.h"
#include "dtls_srtp.h"

#ifndef HAVE_USRSCTP

typedef enum {
  
  DATA_CHANNEL_OPEN = 0x03,
  DATA_CHANNEL_ACK = 0x02,

} decp_msg_type_t;

typedef struct {

  uint16_t type;
  uint16_t length;
  uint8_t value[0];

} sctp_chunk_param_t;

typedef enum {

  SCTP_PARAM_STATE_COOKIE = 7,

} sctp_param_type_t;

typedef enum {

  SCTP_DATA = 0,
  SCTP_INIT = 1,
  SCTP_INIT_ACK = 2,
  SCTP_SACK = 3, 
  SCTP_HEARTBEAT = 4,
  SCTP_HEARTBEAT_ACK = 5,
  SCTP_ABORT = 6, 
  SCTP_SHUTDOWN = 7,
  SCTP_SHUTDOWN_ACK = 8,
  SCTP_ERROR = 9,
  SCTP_COOKIE_ECHO = 10,
  SCTP_COOKIE_ACK = 11,
  SCTP_ECNE = 12,
  SCTP_CWR = 13,
  SCTP_SHUTDOWN_COMPLETE = 14,
  SCTP_AUTH = 15, 
  SCTP_ASCONF_ACK = 128,
  SCTP_ASCONF = 130,
  SCTP_FORWARD_TSN = 192

} sctp_header_type_t;

typedef struct SctpChunkCommon {

  uint8_t type;
  uint8_t flags;
  uint16_t length;

} sctp_chunk_common_t;

typedef struct SctpForwardTsnChunk {

  sctp_chunk_common_t common;
  uint32_t new_cumulative_tsn;
  uint16_t stream_number;
  uint16_t stream_sequence_number;

} sctp_forward_tsn_chunk_t;



typedef struct {

  uint16_t source_port;
  uint16_t destination_port;
  uint32_t verification_tag;
  uint32_t checksum;

} sctp_header_t;

typedef struct {

  sctp_header_t header;
  uint8_t chunks[0];

} sctp_packet_t;

typedef struct {

  sctp_chunk_common_t common;
  uint32_t cumulative_tsn_ack;
  uint32_t a_rwnd;
  uint16_t number_of_gap_ack_blocks;
  uint16_t number_of_dup_tsns;
  uint8_t blocks[0];

} sctp_sack_chunk_t;

typedef struct {

  uint8_t type;
  uint8_t iube;
  uint16_t length;
  uint32_t tsn;
  uint16_t si;
  uint16_t sqn;
  uint32_t ppid;
  uint8_t data[0];

} sctp_data_chunk_t;

typedef struct {

  sctp_chunk_common_t common;
  uint32_t initiate_tag;
  uint32_t a_rwnd;
  uint16_t number_of_outbound_streams;
  uint16_t number_of_inbound_streams;
  uint32_t initial_tsn;
  sctp_chunk_param_t param[0];

} sctp_init_chunk_t;

#endif

typedef enum SctpDataPpid {

  PPID_CONTROL = 50,
  PPID_STRING = 51,
  PPID_BINARY = 53,
  PPID_STRING_EMPTY = 56,
  PPID_BINARY_EMPTY = 57

} sctp_data_ppid_t;

typedef struct {

  struct socket *sock;

  int local_port;
  int remote_port;
  int connected;
  uint32_t verification_tag;
  uint32_t tsn;
  dtls_srtp_t *dtls_srtp;

  /* datachannel */
  void (*onmessasge)(char *msg, size_t len, void *userdata);
  void (*onopen)(void *userdata);
  void (*onclose)(void *userdata);

  void *userdata;
  uint8_t buf[CONFIG_MTU];
} sctp_t;


sctp_t* sctp_create(dtls_srtp_t *dtls_srtp);

void sctp_destroy(sctp_t *sctp);

int sctp_create_socket(sctp_t *sctp, dtls_srtp_t *dtls_srtp);

int sctp_is_connected(sctp_t *sctp);

void sctp_incoming_data(sctp_t *sctp, char *buf, size_t len);

int sctp_outgoing_data(sctp_t *sctp, char *buf, size_t len, sctp_data_ppid_t ppid);

void sctp_onmessage(sctp_t *sctp, void (*onmessasge)(char *msg, size_t len, void *userdata));

void sctp_onopen(sctp_t *sctp, void (*onopen)(void *userdata));

void sctp_onclose(sctp_t *sctp, void (*onclose)(void *userdata));

#endif // SCTP_H_
