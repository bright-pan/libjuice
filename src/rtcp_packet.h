#ifndef RTCP_PACKET_H_
#define RTCP_PACKET_H_

#include <stdint.h>

typedef enum {

    RTCP_FIR = 192,
    RTCP_SR = 200,
    RTCP_RR = 201,
    RTCP_SDES = 202,
    RTCP_BYE = 203,
    RTCP_APP = 204,
    RTCP_RTPFB = 205,
    RTCP_PSFB = 206,
    RTCP_XR = 207,

} rtcp_type_t;

typedef struct {

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint16_t rc:5;
    uint16_t padding:1;
    uint16_t version:2;
    uint16_t type:8;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint16_t version:2;
    uint16_t padding:1;
    uint16_t rc:5;
    uint16_t type:8;
#endif
    uint16_t length:16;

} rtcp_header_t;

typedef struct {

    uint32_t ssrc;
    uint32_t flcnpl;
    uint32_t ehsnr;
    uint32_t jitter;
    uint32_t lsr;
    uint32_t dlsr;

} rtcp_report_block_t;


typedef struct {

    rtcp_header_t header;
    uint32_t ssrc;
    rtcp_report_block_t report_block[1];

} rtcp_rr_t;

typedef struct {

    uint32_t ssrc;
    uint32_t seqnr;

} rtcp_fir_t;

typedef struct {

    rtcp_header_t header;
    uint32_t ssrc;
    uint32_t media;
    char fci[1];

} rtcp_fb_t;

int rtcp_packet_validate(uint8_t *packet, size_t size);

int rtcp_packet_get_pli(uint8_t *packet, int len, uint32_t ssrc);

int rtcp_packet_get_fir(uint8_t *packet, int len, int *seqnr);

rtcp_rr_t rtcp_packet_parse_rr(uint8_t *packet);

#endif // RTCP_PACKET_H_
