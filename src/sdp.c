#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdarg.h>
#include <stdio.h>

#include "sdp.h"

int sdp_append(sdp_t *sdp, const char *format, ...) {

    va_list argptr;

    char attr[SDP_ATTR_LENGTH];

    memset(attr, 0, sizeof(attr));

    va_start(argptr, format);

    vsnprintf(attr, sizeof(attr), format, argptr);

    va_end(argptr);

    strcat(sdp->content, attr);
    strcat(sdp->content, "\r\n");
    return 0;
}

void sdp_reset(sdp_t *sdp) { memset(sdp->content, 0, sizeof(sdp->content)); }

void sdp_append_h264(sdp_t *sdp) {

    sdp_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF 102 103");
    sdp_append(sdp, "a=rtpmap:102 H264/90000");
    // sdp_append(sdp, "a=rtcp-fb:102 goog-remb");
    // sdp_append(sdp, "a=rtcp-fb:102 transport-cc");
    sdp_append(sdp, "a=rtcp-fb:102 ccm fir");
    sdp_append(sdp, "a=rtcp-fb:102 nack");
    sdp_append(sdp, "a=rtcp-fb:102 nack pli");
    sdp_append(sdp, "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f");
    // sdp_append(sdp, "a=rtpmap:103 rtx/90000");
    // sdp_append(sdp, "a=fmtp:103 apt=102");
    sdp_append(sdp, "a=ssrc:123456 cname:webrtc-h264");
    sdp_append(sdp, "a=sendonly");
    sdp_append(sdp, "a=mid:0");
    sdp_append(sdp, "c=IN IP4 0.0.0.0");
    sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcma(sdp_t *sdp) {

    sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 8");
    sdp_append(sdp, "a=rtpmap:8 PCMA/8000");
    sdp_append(sdp, "a=ssrc:4 cname:webrtc-pcma");
    sdp_append(sdp, "a=sendonly");
    sdp_append(sdp, "a=mid:2");
    sdp_append(sdp, "c=IN IP4 0.0.0.0");
    sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcmu(sdp_t *sdp) {

    sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 0");
    sdp_append(sdp, "a=rtpmap:0 PCMU/8000");
    sdp_append(sdp, "a=ssrc:5 cname:webrtc-pcmu");
    sdp_append(sdp, "a=sendrecv");
    sdp_append(sdp, "a=mid:2");
    sdp_append(sdp, "c=IN IP4 0.0.0.0");
    sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_datachannel(sdp_t *sdp) {

    sdp_append(sdp, "m=application 9 UDP/DTLS/SCTP webrtc-datachannel");
    sdp_append(sdp, "a=mid:1");
    sdp_append(sdp, "a=sctp-port:5000");
    sdp_append(sdp, "c=IN IP4 0.0.0.0");
    sdp_append(sdp, "a=max-message-size:262144");
}

void sdp_create(sdp_t *sdp, int b_video, int b_audio, int b_datachannel) {

    char bundle[64];
    sdp_append(sdp, "v=0");
    sdp_append(sdp, "o=- 1495799811084970 1495799811084970 IN IP4 0.0.0.0");
    sdp_append(sdp, "s=-");
    sdp_append(sdp, "t=0 0");
    sdp_append(sdp, "a=msid-semantic: iot");

    memset(bundle, 0, sizeof(bundle));

    strcat(bundle, "a=group:BUNDLE");

    if (b_video) {
        strcat(bundle, " 0");
    }

    if (b_datachannel) {
        strcat(bundle, " 1");
    }

    if (b_audio) {
        strcat(bundle, " 2");
    }


    sdp_append(sdp, bundle);
}
