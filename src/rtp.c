#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdio.h>
#include <string.h>

#include "rtp.h"
#include "rtp_list.h"
#include "socket.h"
#include "timestamp.h"
#include "log.h"


int rtp_packet_validate(uint8_t *packet, size_t size) {

  if(size < 12)
    return 0;

  rtp_header_t *rtp_header = (rtp_header_t*)packet;
  return ((rtp_header->type < 64) || (rtp_header->type >= 96));
}

int is_pframe(nalu_type_t type) {
    return type != NALU_TYPE_PPS && type != NALU_TYPE_SPS && type != NALU_TYPE_IDRSLICE;
}

static int rtp_packetizer_encode_h264_single(rtp_packetizer_t *rtp_packetizer, uint8_t *buf, size_t size) {
    rtp_packet_t *rtp_packet = (rtp_packet_t *)rtp_packetizer->buf;

    rtp_packet->header.version = 2;
    rtp_packet->header.padding = 0;
    rtp_packet->header.extension = 0;
    rtp_packet->header.csrccount = 0;
    rtp_packet->header.markerbit = 0;
    rtp_packet->header.type = rtp_packetizer->type;
    rtp_packet->header.seq_number = htons(rtp_packetizer->seq_number++);
    rtp_packet->header.timestamp = htonl(rtp_packetizer->timestamp);
    rtp_packet->header.ssrc = htonl(rtp_packetizer->ssrc);

    nalu_header_t *nalu_header = (nalu_header_t *)buf;
    if (is_pframe(nalu_header->type)) {
        rtp_packet->header.markerbit = 1;
    }

    memcpy(rtp_packet->payload, buf, size);
    rtp_packetizer->on_packet((char *)rtp_packetizer->buf, size + sizeof(rtp_header_t), rtp_packetizer->user_data);
    return 0;
}

static int rtp_packetizer_encode_h264_fu_a(rtp_packetizer_t *rtp_packetizer, uint8_t *buf, size_t size) {

    rtp_packet_t *rtp_packet = (rtp_packet_t *)rtp_packetizer->buf;

    rtp_packet->header.version = 2;
    rtp_packet->header.padding = 0;
    rtp_packet->header.extension = 0;
    rtp_packet->header.csrccount = 0;
    rtp_packet->header.markerbit = 0;
    rtp_packet->header.type = rtp_packetizer->type;
    rtp_packet->header.seq_number = htons(rtp_packetizer->seq_number++);
    rtp_packet->header.timestamp = htonl(rtp_packetizer->timestamp);
    rtp_packet->header.ssrc = htonl(rtp_packetizer->ssrc);
    // rtp_packetizer->timestamp += 90000/25; // 25 FPS.

    uint8_t type = buf[0] & 0x1f;
    uint8_t nri = (buf[0] & 0x60) >> 5;
    buf = buf + 1;
    size = size - 1;

    nalu_header_t *fu_indicator = (nalu_header_t*)rtp_packet->payload;
    fu_header_t *fu_header = (fu_header_t*)rtp_packet->payload + sizeof(nalu_header_t);
    fu_header->s = 1;

    while (size > 0) {

        fu_indicator->type = FU_A;
        fu_indicator->nri = nri;
        fu_indicator->f = 0;
        fu_header->type = type;
        fu_header->r = 0;

        if (size <= FU_PAYLOAD_SIZE) {

            fu_header->e = 1;
            rtp_packet->header.markerbit = 1;
            memcpy(rtp_packet->payload + sizeof(nalu_header_t) + sizeof(fu_header_t), buf, size);
            rtp_packetizer->on_packet((char* )rtp_packetizer->buf, size + sizeof(rtp_header_t) + sizeof(nalu_header_t) + sizeof(fu_header_t), rtp_packetizer->user_data);
            break;
        }

        fu_header->e = 0;

        memcpy(rtp_packet->payload + sizeof(nalu_header_t) + sizeof(fu_header_t), buf, FU_PAYLOAD_SIZE);
        rtp_packetizer->on_packet((char* )rtp_packetizer->buf, CONFIG_MTU, rtp_packetizer->user_data);
        size -= FU_PAYLOAD_SIZE;
        buf += FU_PAYLOAD_SIZE;

        fu_header->s = 0;
        rtp_packet->header.seq_number = htons(rtp_packetizer->seq_number++);

    }
    return 0;
}

static uint8_t* h264_find_nalu(uint8_t *buf_start, uint8_t *buf_end) {

    uint8_t *p = buf_start + 2;

    while (p < buf_end) {

        if (*(p - 2) == 0x00 && *(p - 1) == 0x00 && *p == 0x01)
            return p + 1;
        p++;
    }

    return buf_end;
}


static int rtp_packetizer_encode_h264(rtp_packetizer_t *rtp_packetizer, uint8_t *buf, size_t size) {
    static nalu_type_t old_nalu_type = NALU_TYPE_SPS;
    uint8_t *buf_end = buf + size;
    uint8_t *pstart, *pend;
    size_t nalu_size = 0;

    for (pstart = h264_find_nalu(buf, buf_end); pstart < buf_end; pstart = pend) {

        pend = h264_find_nalu(pstart, buf_end);
        nalu_size = pend - pstart;

        if (pend != buf_end)
            nalu_size--;

        while (pstart[nalu_size - 1] == 0x00)
            nalu_size--;

        nalu_header_t *nalu_header = (nalu_header_t *)pstart;
        if (is_pframe(old_nalu_type)) {
            if (!is_pframe(nalu_header->type)) {
                if (rtp_packetizer->timestamp % 90000) {
                    rtp_packetizer->timestamp += 90000;
                }
                rtp_packetizer->timestamp -= rtp_packetizer->timestamp % 90000;
            } else {
                rtp_packetizer->timestamp += 90000/30; // 30 FPS.
            }
        } else {
            if (is_pframe(nalu_header->type)) {
                rtp_packetizer->timestamp += 90000/30; // 30 FPS.
            }
        }
        old_nalu_type = nalu_header->type;
        if (nalu_size <= RTP_PAYLOAD_SIZE) {
            rtp_packetizer_encode_h264_single(rtp_packetizer, pstart, nalu_size);
        } else {
            rtp_packetizer_encode_h264_fu_a(rtp_packetizer, pstart, nalu_size);
        }
    }
    return nalu_size;

}

static int rtp_packetizer_encode_generic(rtp_packetizer_t *rtp_packetizer, uint8_t *buf, size_t size) {
    int ret = -1;
    rtp_header_t *rtp_header = (rtp_header_t*)rtp_packetizer->buf;
    rtp_header->version = 2;
    rtp_header->padding = 0;
    rtp_header->extension = 0;
    rtp_header->csrccount = 0;
    rtp_header->markerbit = 0;
    rtp_header->type = rtp_packetizer->type;
    rtp_header->seq_number = htons(rtp_packetizer->seq_number++);
    rtp_packetizer->timestamp += size; // 8000 HZ.
    rtp_header->timestamp = htonl(rtp_packetizer->timestamp);
    rtp_header->ssrc = htonl(rtp_packetizer->ssrc);
    if (size <= RTP_PACKETIZER_BUF_SIZE) {
        memcpy(rtp_packetizer->buf + sizeof(rtp_header_t), buf, size);
        rtp_packetizer->on_packet((char *)rtp_packetizer->buf, size + sizeof(rtp_header_t), rtp_packetizer->user_data);
        ret = 0;
    } else {
        JLOG_ERROR("rtp_packetizer packet size %ld is too large > %d", size, RTP_PACKETIZER_BUF_SIZE);
    }

    return ret;
}

static int rtp_packetizer_encode_rtx(rtp_packetizer_t *rtp_packetizer, uint8_t *buf, size_t size) {
    int ret = -1;
    rtp_header_t *rtp_header = (rtp_header_t*)rtp_packetizer->buf;
    rtp_header->version = 2;
    rtp_header->padding = 0;
    rtp_header->extension = 0;
    rtp_header->csrccount = 0;
    rtp_header->markerbit = 0;
    rtp_header->type = rtp_packetizer->type;
    rtp_header->seq_number = htons(rtp_packetizer->seq_number++);
    rtp_header->timestamp = ((rtp_header_t *)buf)->timestamp;
    rtp_header->ssrc = htonl(rtp_packetizer->ssrc);
    if (size + 2 <= RTP_PACKETIZER_BUF_SIZE) {
        rtp_rtx_t *rtx = (rtp_rtx_t *)(rtp_packetizer->buf + sizeof(rtp_header_t));
        rtx->osn = htons(((rtp_header_t *)buf)->seq_number); // set osn
        memcpy(rtx->payload, buf + sizeof(rtp_header_t),  size - sizeof(rtp_header_t));
        rtp_packetizer->on_packet((char *)rtp_packetizer->buf, size + 2, rtp_packetizer->user_data);
        ret = 0;
    } else {
        JLOG_ERROR("rtp_packetizer_encode_rtx packet size %ld is too large > %d", size + 2, RTP_PACKETIZER_BUF_SIZE);
    }

    return ret;
}

void rtp_packetizer_init(rtp_packetizer_t *rtp_packetizer, media_codec_t codec, uint32_t timestamp, void (*on_packet)(char *packet, int bytes, void *user_data), void *user_data) {

    rtp_packetizer->on_packet = on_packet;
    rtp_packetizer->user_data = user_data;
    rtp_packetizer->timestamp = timestamp;
    rtp_packetizer->seq_number = 0;

    switch (codec) {

        case MEDIA_CODEC_H264:
            rtp_packetizer->type = RTP_PAYLOAD_TYPE_H264;
            rtp_packetizer->ssrc = RTP_SSRC_TYPE_H264;
            rtp_packetizer->encode_func = rtp_packetizer_encode_h264;
            break;
        case MEDIA_CODEC_PCMA:
            rtp_packetizer->type = RTP_PAYLOAD_TYPE_PCMA;
            rtp_packetizer->ssrc = RTP_SSRC_TYPE_PCMA;
            rtp_packetizer->encode_func = rtp_packetizer_encode_generic;
            break;
        case MEDIA_CODEC_PCMU:
            rtp_packetizer->type = RTP_PAYLOAD_TYPE_PCMU;
            rtp_packetizer->ssrc = RTP_SSRC_TYPE_PCMU;
            rtp_packetizer->encode_func = rtp_packetizer_encode_generic;
            break;
        case MEDIA_CODEC_H264_RTX:
            rtp_packetizer->type = RTP_PAYLOAD_TYPE_H264_RTX;
            rtp_packetizer->ssrc = RTP_SSRC_TYPE_H264_RTX;
            rtp_packetizer->encode_func = rtp_packetizer_encode_rtx;
            break;
        default:
        break;
    }
}

int rtp_packetizer_encode(rtp_packetizer_t *rtp_packetizer, void *buf, size_t size) {
    return rtp_packetizer->encode_func(rtp_packetizer, buf, size);
}