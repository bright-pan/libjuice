#ifndef RTP_H_
#define RTP_H_

#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdint.h>
#include "codec.h"

typedef enum {

    RTP_PAYLOAD_TYPE_PCMU = 0,
    RTP_PAYLOAD_TYPE_PCMA = 8,
    RTP_PAYLOAD_TYPE_G722 = 9,
    RTP_PAYLOAD_TYPE_H264 = 102,
    RTP_PAYLOAD_TYPE_H264_RTX = 103,// rtx
    RTP_PAYLOAD_TYPE_OPUS = 111

} rtp_payload_type_t;

typedef enum {

    RTP_SSRC_TYPE_H264 = 9527,
    RTP_SSRC_TYPE_H264_RTX = 9528,
    RTP_SSRC_TYPE_PCMA = 4,
    RTP_SSRC_TYPE_PCMU = 5,
    RTP_SSRC_TYPE_OPUS = 6,

} rtp_ssrc_type_t;

typedef struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint16_t version : 2;
    uint16_t padding : 1;
    uint16_t extension : 1;
    uint16_t csrccount : 4;
    uint16_t markerbit : 1;
    uint16_t type : 7;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint16_t csrccount : 4;
    uint16_t extension : 1;
    uint16_t padding : 1;
    uint16_t version : 2;
    uint16_t type : 7;
    uint16_t markerbit : 1;
#endif
    uint16_t seq_number;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc[0];

} rtp_header_t;

typedef struct {

    rtp_header_t header;
    uint8_t payload[0];

} rtp_packet_t;

typedef struct {

    uint16_t osn;
    uint8_t payload[0];

} rtp_rtx_t;

typedef struct {

    int pt_h264;
    int pt_opus;
    int pt_pcma;

} rtp_map_t;


typedef struct rtp_packetizer rtp_packetizer_t;

struct rtp_packetizer {

    rtp_payload_type_t type;
    void (*on_packet)(char *packet, int bytes, void *user_data);
    int (*encode_func)(rtp_packetizer_t *rtp_packetizer, uint8_t *buf, size_t size);
    void *user_data;
    uint16_t seq_number;
    uint32_t ssrc;
    uint32_t timestamp;
    uint8_t buf[RTP_PACKETIZER_BUF_SIZE];
};

int rtp_packet_validate(uint8_t *packet, size_t size);

void rtp_packetizer_init(rtp_packetizer_t *rtp_packetizer, media_codec_t codec, uint32_t timestamp,
                         void (*on_packet)(char *packet, int bytes, void *user_data),
                         void *user_data);

int rtp_packetizer_encode(rtp_packetizer_t *rtp_packetizer, void *buf, size_t size);

#endif // RTP_H_
