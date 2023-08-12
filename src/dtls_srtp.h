#ifndef DTLS_SRTP_H_
#define DTLS_SRTP_H_

#include <stdio.h>
#include <stdlib.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>

#include <srtp.h>

#include "addr.h"

#define SRTP_MASTER_KEY_LENGTH  16
#define SRTP_MASTER_SALT_LENGTH 14
#define DTLS_SRTP_KEY_MATERIAL_LENGTH 60
#define DTLS_SRTP_FINGERPRINT_LENGTH 160

typedef enum dtls_srtp_role {

    DTLS_SRTP_ROLE_CLIENT,
    DTLS_SRTP_ROLE_SERVER

} dtls_srtp_role_t;

typedef enum dlts_srtp_state {

    DTLS_SRTP_STATE_INIT,
    DTLS_SRTP_STATE_HANDSHAKE,
    DTLS_SRTP_STATE_CONNECTED

} dlts_srtp_state_t;

typedef struct dtls_srtp {

    // MbedTLS
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // SRTP
    srtp_policy_t remote_policy;
    srtp_policy_t local_policy;
    srtp_t srtp_in;
    srtp_t srtp_out;
    unsigned char remote_policy_key[SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH];
    unsigned char local_policy_key[SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH];

    mbedtls_ssl_send_t *udp_send;
    mbedtls_ssl_recv_t *udp_recv;

    addr_record_t *remote_addr;

    dtls_srtp_role_t role;
    dlts_srtp_state_t state;

    char local_fingerprint[DTLS_SRTP_FINGERPRINT_LENGTH];
    char remote_fingerprint[DTLS_SRTP_FINGERPRINT_LENGTH];

    void *user_data;

    int ssl_debug_enable;
    int ssl_debug_level;

} dtls_srtp_t;

void dtls_srtp_ssl_dbg_init(dtls_srtp_t *dtls_srtp, int enable, int level);
int dtls_srtp_init(dtls_srtp_t *dtls_srtp, dtls_srtp_role_t role, void *user_data);

void dtls_srtp_deinit(dtls_srtp_t *dtls_srtp);

int dtls_srtp_create_cert(dtls_srtp_t *dtls_srtp);

int dtls_srtp_handshake(dtls_srtp_t *dtls_srtp, addr_record_t *addr);

void dtls_srtp_reset_session(dtls_srtp_t *dtls_srtp);

int dtls_srtp_write(dtls_srtp_t *dtls_srtp, const char *buf, size_t len);

int dtls_srtp_read(dtls_srtp_t *dtls_srtp, char *buf, size_t len);

void dtls_srtp_sctp_to_dtls(dtls_srtp_t *dtls_srtp, unsigned char *packet, int bytes);

int dtls_srtp_validate(unsigned char *buf);

int dtls_srtp_decrypt_rtp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes);

int dtls_srtp_decrypt_rtcp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes);

int dtls_srtp_encrypt_rtp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes);

int dtls_srtp_encrypt_rctp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes);

#endif // DTLS_SRTP_H_

