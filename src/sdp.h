#ifndef SDP_H_
#define SDP_H_

#include <string.h>
#include "juice.h"

#define SDP_CONTENT_LENGTH JUICE_MAX_SDP_STRING_LEN
#define SDP_ATTR_LENGTH 128

typedef struct sdp_t {

    char content[SDP_CONTENT_LENGTH];

} sdp_t;

void sdp_append_h264(sdp_t *sdp);
  
void sdp_append_pcma(sdp_t *sdp);
  
void sdp_append_datachannel(sdp_t *sdp);

void sdp_create(sdp_t *sdp, int b_video, int b_audio, int b_datachannel);

int sdp_append(sdp_t *sdp, const char *format, ...);

void sdp_reset(sdp_t *sdp);

#endif // SDP_H_
