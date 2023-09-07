#ifndef __RTP_ENC_H__
#define __RTP_ENC_H__

#include "peer_connection.h"

void rtp_enc_init(peer_connection_t *pc);
void rtp_enc_start(peer_connection_t *pc);
void rtp_enc_stop(peer_connection_t *pc);
void rtp_enc_restart(peer_connection_t *pc);

void rtp_dec_init(peer_connection_t *pc);
void rtp_dec_start(peer_connection_t *pc);
void rtp_dec_stop(peer_connection_t *pc);
void rtp_dec_restart(peer_connection_t *pc);

#endif
