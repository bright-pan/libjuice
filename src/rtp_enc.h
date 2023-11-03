#ifndef __RTP_ENC_H__
#define __RTP_ENC_H__

#include "peer_connection.h"

void rtp_video_enc_init(peer_connection_t *pc);
void rtp_video_enc_start(peer_connection_t *pc);
void rtp_video_enc_stop(peer_connection_t *pc);
void rtp_video_enc_restart(peer_connection_t *pc);

void rtp_audio_enc_init(peer_connection_t *pc);
void rtp_audio_enc_start(peer_connection_t *pc);
void rtp_audio_enc_stop(peer_connection_t *pc);
void rtp_audio_enc_restart(peer_connection_t *pc);

void rtp_enc_init(peer_connection_t *pc);
void rtp_enc_start(peer_connection_t *pc);
void rtp_enc_stop(peer_connection_t *pc);
void rtp_enc_restart(peer_connection_t *pc);

void rtp_audio_dec_init(peer_connection_t *pc);
void rtp_audio_dec_start(peer_connection_t *pc);
void rtp_audio_dec_stop(peer_connection_t *pc);
void rtp_audio_dec_restart(peer_connection_t *pc);

void rtp_dec_init(peer_connection_t *pc);
void rtp_dec_start(peer_connection_t *pc);
void rtp_dec_stop(peer_connection_t *pc);
void rtp_dec_restart(peer_connection_t *pc);

int rtcp_psfb_pli_process(void);
void *rtp_audio_enc_thread_entry(void *param);
void *rtp_audio_dec_thread_entry(void *param);

#endif
