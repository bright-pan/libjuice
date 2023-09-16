#ifndef RTCP_PACKET_H_
#define RTCP_PACKET_H_

#include <stdint.h>
/*
————————————————
RTCP 协议规范中定义了五种类型的 RTCP 包：接收⽅报告（ RR ）、发送⽅报告（ SR ）、源
描述（ SDES ）、成员管理（ BYE ）和应⽤程序定义（ APP ）。
SR: payload type=200
RR:payload type=201
SDES: payload type=202
BYE:payload type=203
APP：payload type=204
RTPFB：payload type=205
PSFB：payload type=206
————————————————
RTCP_RTP_FB_NACK_FMT(1): NACK重传, type-205
RTCP_RTP_FB_RTX_FMT(1):RTX重传，type-205
RTCP_RTP_FB_CC_FMT(15):Transport-cc 带宽估计，type-205
————————————————
RTCP_PLI_FMT(1): picture重传, type-206
RTCP_SLI_FMT(2): Slice重传, type-206
RTCP_FIR_FMT(4): 关键帧重传, type-206
RTCP_REMB_FMT(15): 带宽估计, type-206
————————————————
*/

#define NACK_BLOCK_SIZE 10
#define SSRC_FEEDBACK_BLOCK_SIZE 5
#define REPORT_BLOCK_SIZE 5

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

typedef enum {

    RTCP_FMT_RTPFB_NACK = 1,
    RTCP_FMT_RTPFB_CC = 15,
    RTCP_FMT_PSFB_PLI = 1,
    RTCP_FMT_PSFB_FIR = 4,
    RTCP_FMT_PSFB_REMB = 15

} rtcp_fmt_t;

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
    uint32_t rsrc;
    uint32_t flcnpl;
    uint32_t ehsnr;
    uint32_t jitter;
    uint32_t lsr;
    uint32_t dlsr;
} rtcp_report_block_t;

typedef struct {
    uint16_t pid; // packet identifier
    uint16_t lostmap; // bitmap of lost packets
} rtcp_rtpfb_nack_block_t;

typedef struct {

    rtcp_header_t header;
    uint32_t ssrc_ps;// packet sender
    uint32_t ssrc_ms;// media source
    rtcp_rtpfb_nack_block_t nack_block[NACK_BLOCK_SIZE];

} rtcp_rtpfb_nack_t;

typedef struct {

    uint32_t ssrc_ps;// packet sender
    uint32_t ssrc_ms;// media source

} rtcp_psfb_pli_block_t;

typedef struct {

    rtcp_header_t header;
    rtcp_psfb_pli_block_t pli_block[1];

} rtcp_psfb_pli_t;

typedef struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t mantissa:18;
    uint32_t exp:6;
    uint32_t num_ssrc:8;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint32_t num_ssrc:8;
    uint32_t exp:6;
    uint32_t mantissa:18;
#endif
} rtcp_psfb_remb_br_t;

typedef struct {
    rtcp_header_t header;
    uint32_t ssrc_ps;// packet sender
    uint32_t ssrc_ms;// media source
    uint32_t remb;
    uint32_t br;
    uint32_t ssrc_feedback_block[SSRC_FEEDBACK_BLOCK_SIZE];
} rtcp_psfb_remb_t;

typedef struct {

    rtcp_header_t header;
    uint32_t ssrc;
    rtcp_report_block_t report_block[REPORT_BLOCK_SIZE];

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
rtcp_rtpfb_nack_t rtcp_packet_parse_rtpfb_nack(uint8_t *packet);
rtcp_psfb_pli_t rtcp_packet_parse_psfb_pli(uint8_t *packet);
// rtcp_psfb_remb_t rtcp_packet_parse_psfb_remb(uint8_t *packet);

#endif // RTCP_PACKET_H_
