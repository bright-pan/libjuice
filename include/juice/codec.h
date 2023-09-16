#ifndef CODEC_H_
#define CODEC_H_

#include <stdlib.h>
#include <stdint.h>

typedef enum {

  MEDIA_CODEC_NONE = 0,

  /* Video */
  MEDIA_CODEC_H264,
  MEDIA_CODEC_H264_RTX, //rtx
  MEDIA_CODEC_VP8, // not implemented yet
  MEDIA_CODEC_MJPEG, // not implemented yet

  /* Audio */
  MEDIA_CODEC_OPUS, // not implemented yet
  MEDIA_CODEC_PCMA,
  MEDIA_CODEC_PCMU

} media_codec_t;

#endif // CODEC_H_

