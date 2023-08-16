#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdio.h>
#include <string.h>

#include "rtcp_packet.h"
#include "rtp.h"
#include "socket.h"

int rtcp_packet_validate(uint8_t *packet, size_t size) {

    if (size < 8)
        return -1;

    rtp_header_t *header = (rtp_header_t *)packet;
    return ((header->type >= 64) && (header->type < 96));
}

int rtcp_packet_get_pli(uint8_t *packet, int len, uint32_t ssrc) {

    if (packet == NULL || len != 12)
        return -1;

    memset(packet, 0, len);
    rtcp_header_t *rtcp_header = (rtcp_header_t *)packet;
    rtcp_header->version = 2;
    rtcp_header->type = RTCP_PSFB;
    rtcp_header->rc = 1;
    rtcp_header->length = htons((len / 4) - 1);
    memcpy(packet + 8, &ssrc, 4);

    return 12;
}

int rtcp_packet_get_fir(uint8_t *packet, int len, int *seqnr) {

    if (packet == NULL || len != 20 || seqnr == NULL)
        return -1;

    memset(packet, 0, len);
    rtcp_header_t *rtcp = (rtcp_header_t *)packet;
    *seqnr = *seqnr + 1;
    if (*seqnr < 0 || *seqnr >= 256)
        *seqnr = 0;

    rtcp->version = 2;
    rtcp->type = RTCP_PSFB;
    rtcp->rc = 4;
    rtcp->length = htons((len / 4) - 1);
    rtcp_fb_t *rtcp_fb = (rtcp_fb_t *)rtcp;
    rtcp_fir_t *fir = (rtcp_fir_t *)rtcp_fb->fci;
    fir->seqnr = htonl(*seqnr << 24);

    return 20;
}

rtcp_rr_t rtcp_packet_parse_rr(uint8_t *packet) {

    rtcp_rr_t rtcp_rr;
    memcpy(&rtcp_rr.header, packet, sizeof(rtcp_rr.header));
    memcpy(&rtcp_rr.report_block[0], packet + 4, ntohs(rtcp_rr.header.length) * sizeof(uint32_t));

    return rtcp_rr;
}

rtcp_rtpfb_nack_t rtcp_packet_parse_rtpfb_nack(uint8_t *packet) {

    rtcp_rtpfb_nack_t rtcp_rtpfb_nack;
    memcpy(&rtcp_rtpfb_nack.header, packet, sizeof(rtcp_rtpfb_nack.header));
    memcpy(&rtcp_rtpfb_nack.nack_block[0], packet + 4, ntohs(rtcp_rtpfb_nack.header.length) * sizeof(uint32_t));

    return rtcp_rtpfb_nack;
}

rtcp_psfb_pli_t rtcp_packet_parse_psfb_pli(uint8_t *packet) {

    rtcp_psfb_pli_t rtcp_psfb_pli;
    memcpy(&rtcp_psfb_pli.header, packet, sizeof(rtcp_psfb_pli.header));
    memcpy(&rtcp_psfb_pli.pli_block[0], packet + 4, ntohs(rtcp_psfb_pli.header.length) * sizeof(uint32_t));

    return rtcp_psfb_pli;
}

rtcp_psfb_remb_t rtcp_packet_parse_psfb_remb(uint8_t *packet) {

    rtcp_psfb_remb_t rtcp_psfb_remb;
    memcpy(&rtcp_psfb_remb.header, packet, sizeof(rtcp_psfb_remb.header));
    memcpy(&rtcp_psfb_remb.remb_block[0], packet + 4, ntohs(rtcp_psfb_remb.header.length) * sizeof(uint32_t));

    return rtcp_psfb_remb;
}