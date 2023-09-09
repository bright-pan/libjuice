#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtls_srtp.h"
#include "udp.h"
#include "log.h"


#define RSA_KEY_LENGTH 2048
#define READ_TIMEOUT_MS 3000


int dtls_srtp_udp_send(void *ctx, const char *buf, size_t len) {

    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *)ctx;
    socket_t *udp_socket = (socket_t *)dtls_srtp->user_data;

    int ret = juice_udp_sendto(*udp_socket, buf, len, dtls_srtp->remote_addr);

    JLOG_INFO("dtls send: %d", ret);

    return ret;
}

int dtls_srtp_udp_recv(void *ctx, char *buf, size_t len) {

    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *)ctx;
    socket_t *udp_socket = (socket_t *)dtls_srtp->user_data;
    addr_record_t _addr;

    // static char buffer[JUICE_MAX_ADDRESS_STRING_LEN];
    int ret;
    // addr_record_to_string(&_addr, buffer, JUICE_MAX_ADDRESS_STRING_LEN);
    // JLOG_INFO("dtls_srtp_udp_recv start %s", buffer);
    while ((ret = udp_recvfrom(*udp_socket, buf, len, &_addr)) <= 0) {
        usleep(1000);
    }
    JLOG_INFO("dtls recv: %d", ret);
    // JLOG_DEBUG("dtls_srtp_udp_recv (%d)", ret);
    // JLOG_ADDR_RECORD(&_addr);

    return ret;
}

static void dtls_srtp_x509_digest(const mbedtls_x509_crt *crt, char *buf) {

    int i;
    unsigned char digest[32];

    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
    mbedtls_sha256_finish(&sha256_ctx, (unsigned char *)digest);
    mbedtls_sha256_free(&sha256_ctx);

    for (i = 0; i < 32; i++) {

        snprintf(buf, 4, "%.2X:", digest[i]);
        buf += 3;
    }

    *(--buf) = '\0';
}

// Do not verify CA
static int dtls_srtp_cert_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {

    *flags &= ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH);
    return 0;
}
/*
static int dtls_srtp_selfsign_cert_with_rsa(dtls_srtp_t *dtls_srtp) {

    int ret;

    mbedtls_x509write_cert crt;

    mbedtls_mpi serial;

    unsigned char *cert_buf = (unsigned char *)juice_malloc(RSA_KEY_LENGTH * 2);

    const char *pers = "dtls_srtp";

    mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy,
                          (const unsigned char *)pers, strlen(pers));

    mbedtls_pk_setup(&dtls_srtp->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    mbedtls_rsa_gen_key(mbedtls_pk_rsa(dtls_srtp->pkey), mbedtls_ctr_drbg_random,
                        &dtls_srtp->ctr_drbg, RSA_KEY_LENGTH, 65537);

    mbedtls_x509write_crt_init(&crt);

    mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

    mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

    mbedtls_x509write_crt_set_issuer_key(&crt, &dtls_srtp->pkey);

    mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");

    mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");

    mbedtls_mpi_init(&serial);

    mbedtls_mpi_fill_random(&serial, 16, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

    mbedtls_x509write_crt_set_serial(&crt, &serial);

    mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20280101000000");

    ret = mbedtls_x509write_crt_pem(&crt, cert_buf, 2 * RSA_KEY_LENGTH, mbedtls_ctr_drbg_random,
                                    &dtls_srtp->ctr_drbg);

    if (ret < 0) {

        JLOG_DEBUG("mbedtls_x509write_crt_pem failed\n");
    }

    mbedtls_x509_crt_parse(&dtls_srtp->cert, cert_buf, 2 * RSA_KEY_LENGTH);

    mbedtls_x509write_crt_free(&crt);

    mbedtls_mpi_free(&serial);

    juice_free(cert_buf);

    return ret;
}
*/

static int dtls_srtp_selfsign_cert_with_ecdsa(dtls_srtp_t *dtls_srtp) {

    int ret;

    mbedtls_x509write_cert crt;

    mbedtls_mpi serial;

    unsigned char *cert_buf = (unsigned char *)juice_malloc(RSA_KEY_LENGTH * 2);
    // memset(cert_buf, 0, RSA_KEY_LENGTH * 2);
    const char *pers = "dtls_srtp";

    mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy,
                          (const unsigned char *)pers, strlen(pers));

    ret = mbedtls_pk_setup(&dtls_srtp->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

    if (ret < 0) {

        JLOG_DEBUG("mbedtls_pk_setup failed, ret=%d\n", ret);
    }

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(dtls_srtp->pkey), mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

    if (ret < 0) {

        JLOG_DEBUG("mbedtls_ecp_gen_key failed, ret=%d\n", ret);
    }

    // mbedtls_pk_write_key_pem(&dtls_srtp->pkey, cert_buf, RSA_KEY_LENGTH * 2);

    // JLOG_INFO("%s", cert_buf);
    mbedtls_x509write_crt_init(&crt);

    mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

    mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

    mbedtls_x509write_crt_set_issuer_key(&crt, &dtls_srtp->pkey);

    mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");

    mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");

    mbedtls_mpi_init(&serial);

    mbedtls_mpi_fill_random(&serial, 16, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

    mbedtls_x509write_crt_set_serial(&crt, &serial);

    mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20280101000000");

    ret = mbedtls_x509write_crt_pem(&crt, cert_buf, 2 * RSA_KEY_LENGTH, mbedtls_ctr_drbg_random,
                                    &dtls_srtp->ctr_drbg);

    if (ret < 0) {

        JLOG_DEBUG("mbedtls_x509write_crt_pem failed, ret=%d\n", ret);
    }

    mbedtls_x509_crt_parse(&dtls_srtp->cert, cert_buf, 2 * RSA_KEY_LENGTH);
    JLOG_INFO("%s", cert_buf);
    mbedtls_x509write_crt_free(&crt);

    mbedtls_mpi_free(&serial);

    juice_free(cert_buf);

    return ret;
}

void dtls_srtp_ssl_dbg_init(dtls_srtp_t *dtls_srtp, int enable, int level) {
    JLOG_DEBUG("init ssl debug: %s, level=%d", enable ? "on": "off", level);
    dtls_srtp->ssl_debug_enable = enable;
    dtls_srtp->ssl_debug_level = level;
}
/*
static void dtls_srtp_libsrtp_init(void) {
    static int flag = 0;
    if (!flag) {
        flag = 1;
        if (srtp_init() != srtp_err_status_ok) {
            JLOG_ERROR("libsrtp init failed");
        } else {
            JLOG_INFO("libsrtp init success");
        }
    }
}
*/

void srtp_log_handler(srtp_log_level_t level,
                                  const char *msg,
                                  void *data)
{
    (void)data;
    char level_char = '?';
    switch (level) {
        case srtp_log_level_error:
            level_char = 'e';
            break;
        case srtp_log_level_warning:
            level_char = 'w';
            break;
        case srtp_log_level_info:
            level_char = 'i';
            break;
        case srtp_log_level_debug:
            level_char = 'd';
            break;
    }
    fprintf(stdout, "SRTP-LOG [%c]: %s\n", level_char, msg);
    fflush(stdout);
}


int dtls_srtp_init(dtls_srtp_t *dtls_srtp, dtls_srtp_role_t role, void *user_data) {

    static const mbedtls_ssl_srtp_profile default_profiles[] = {

        MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80, 
        MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32,
        MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80, 
        MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32,
        MBEDTLS_TLS_SRTP_UNSET
    };

    dtls_srtp->role = role;
    dtls_srtp->state = DTLS_SRTP_STATE_INIT;
    dtls_srtp->user_data = user_data;
    dtls_srtp->udp_send = (mbedtls_ssl_send_t *)dtls_srtp_udp_send;
    dtls_srtp->udp_recv = (mbedtls_ssl_recv_t *)dtls_srtp_udp_recv;

    mbedtls_ssl_config_init(&dtls_srtp->conf);
    mbedtls_ssl_init(&dtls_srtp->ssl);

    mbedtls_x509_crt_init(&dtls_srtp->cert);
    mbedtls_pk_init(&dtls_srtp->pkey);
    mbedtls_entropy_init(&dtls_srtp->entropy);
    mbedtls_ctr_drbg_init(&dtls_srtp->ctr_drbg);

    dtls_srtp_selfsign_cert_with_ecdsa(dtls_srtp);

#if defined(CONFIG_LIBJUICE_USE_MBEDTLS) && defined(MBEDTLS_DEBUG_C)
    if (dtls_srtp->ssl_debug_enable && dtls_srtp->role == DTLS_SRTP_ROLE_CLIENT) {
        mbedtls_ssl_conf_dbg(&dtls_srtp->conf, _ssl_debug, NULL);
        mbedtls_debug_set_threshold(dtls_srtp->ssl_debug_level);
    }
#endif

    mbedtls_ssl_conf_verify(&dtls_srtp->conf, dtls_srtp_cert_verify, NULL);

    mbedtls_ssl_conf_authmode(&dtls_srtp->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);

    mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &dtls_srtp->cert, &dtls_srtp->pkey);

    mbedtls_ssl_conf_rng(&dtls_srtp->conf, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

    mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, READ_TIMEOUT_MS);

    if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {

        mbedtls_ssl_config_defaults(&dtls_srtp->conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);

        mbedtls_ssl_cookie_init(&dtls_srtp->cookie_ctx);

        mbedtls_ssl_cookie_setup(&dtls_srtp->cookie_ctx, mbedtls_ctr_drbg_random,
                                 &dtls_srtp->ctr_drbg);

        mbedtls_ssl_conf_dtls_cookies(&dtls_srtp->conf, mbedtls_ssl_cookie_write,
                                      mbedtls_ssl_cookie_check, &dtls_srtp->cookie_ctx);

    } else {

        mbedtls_ssl_config_defaults(&dtls_srtp->conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
    }

    dtls_srtp_x509_digest(&dtls_srtp->cert, dtls_srtp->local_fingerprint);

    JLOG_DEBUG("local fingerprint: %s", dtls_srtp->local_fingerprint);

    mbedtls_ssl_conf_dtls_srtp_protection_profiles(&dtls_srtp->conf, default_profiles);

    mbedtls_ssl_conf_srtp_mki_value_supported(&dtls_srtp->conf,
                                              MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED);

    mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);
    srtp_install_log_handler(srtp_log_handler, NULL);
    if (srtp_init() != srtp_err_status_ok) {
        JLOG_ERROR("libsrtp init failed");
    } else {
        JLOG_INFO("libsrtp init success");
    }

    return 0;
}

void dtls_srtp_deinit(dtls_srtp_t *dtls_srtp) {

    mbedtls_ssl_free(&dtls_srtp->ssl);
    mbedtls_ssl_config_free(&dtls_srtp->conf);

    mbedtls_x509_crt_free(&dtls_srtp->cert);
    mbedtls_pk_free(&dtls_srtp->pkey);
    mbedtls_entropy_free(&dtls_srtp->entropy);
    mbedtls_ctr_drbg_free(&dtls_srtp->ctr_drbg);

    if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {

        mbedtls_ssl_cookie_free(&dtls_srtp->cookie_ctx);
    }

    if (dtls_srtp->state == DTLS_SRTP_STATE_CONNECTED) {

        srtp_dealloc(dtls_srtp->srtp_in);
        srtp_dealloc(dtls_srtp->srtp_out);
    }

    srtp_shutdown();
}

static void dtls_srtp_key_derivation(void *context, mbedtls_ssl_key_export_type secret_type,
                                     const unsigned char *secret, size_t secret_len,
                                     const unsigned char client_random[32],
                                     const unsigned char server_random[32],
                                     mbedtls_tls_prf_types tls_prf_type) {

    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *)context;

    int ret;

    const char *dtls_srtp_label = "EXTRACTOR-dtls_srtp";

    unsigned char randbytes[64];

    unsigned char key_material[DTLS_SRTP_KEY_MATERIAL_LENGTH];

    memcpy(randbytes, client_random, 32);
    memcpy(randbytes + 32, server_random, 32);

    const mbedtls_ssl_ciphersuite_t *suite_info;
    suite_info = mbedtls_ssl_ciphersuite_from_id(dtls_srtp->ssl.private_session_negotiate->private_ciphersuite);

    JLOG_INFO("tls_prf_type: %d selected ciphersuite: %s, srtp profile: %s", tls_prf_type, suite_info->private_name,
               mbedtls_ssl_get_srtp_profile_as_string(dtls_srtp->ssl.private_dtls_srtp_info.private_chosen_dtls_srtp_profile));
    JLOG_INFO_DUMP_HEX(secret, secret_len, "----------------secret[%d]----------------------", secret_len);

	if (dtls_srtp->ssl.private_dtls_srtp_info.private_chosen_dtls_srtp_profile != MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80)
    {
        JLOG_ERROR("Failed selected SRTP profile MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80");
        return;
    }

	const srtp_profile_t srtpProfile = srtp_profile_aes128_cm_sha1_80;
	const size_t keySize = SRTP_AES_128_KEY_LEN;
	const size_t saltSize = SRTP_SALT_LEN;
	const size_t keySizeWithSalt = SRTP_AES_ICM_128_KEY_LEN_WSALT;

    // Export keying material
    if ((ret = mbedtls_ssl_tls_prf(tls_prf_type, secret, secret_len, dtls_srtp_label, randbytes,
                                   sizeof(randbytes), key_material, sizeof(key_material))) != 0) {

        JLOG_ERROR("mbedtls_ssl_tls_prf failed(%d)", ret);
        return;
    }
	// Order is client key, server key, client salt, and server salt
	const unsigned char *clientKey = key_material;
	const unsigned char *serverKey = clientKey + keySize;
	const unsigned char *clientSalt = serverKey + keySize;
	const unsigned char *serverSalt = clientSalt + saltSize;

    JLOG_INFO("client key[%d],  client salt[%d], server key[%d], server salt[%d]", keySize, saltSize, keySize, saltSize);
    JLOG_INFO_DUMP_HEX(clientKey, keySize, "------------clientKey[%d]--------------", keySize);
    JLOG_INFO_DUMP_HEX(clientSalt, saltSize, "------------clientSalt[%d]--------------", keySize);
    JLOG_INFO_DUMP_HEX(serverKey, keySize, "------------serverKey[%d]--------------", keySize);
    JLOG_INFO_DUMP_HEX(serverSalt, saltSize, "------------serverSalt[%d]--------------", keySize);

    memcpy(dtls_srtp->remote_policy_key, serverKey, keySize);
    memcpy(dtls_srtp->remote_policy_key + keySize, serverSalt, saltSize);

    memcpy(dtls_srtp->local_policy_key, clientKey, keySize);
    memcpy(dtls_srtp->local_policy_key + keySize, clientSalt, saltSize);

    // derive inbounds keys
	srtp_policy_t inbound = {};
	srtp_crypto_policy_set_from_profile_for_rtp(&inbound.rtp, srtpProfile);
	srtp_crypto_policy_set_from_profile_for_rtcp(&inbound.rtcp, srtpProfile);
	inbound.ssrc.type = ssrc_any_inbound;

	inbound.key = (dtls_srtp->role == DTLS_SRTP_ROLE_CLIENT) ? dtls_srtp->remote_policy_key : dtls_srtp->local_policy_key;

	inbound.window_size = 1024;
	inbound.allow_repeat_tx = true;
	inbound.next = NULL;

    dtls_srtp->remote_policy = inbound;

    if ((ret = srtp_create(&dtls_srtp->srtp_in, &dtls_srtp->remote_policy)) != srtp_err_status_ok) {

        JLOG_DEBUG("Error creating inbound SRTP session, ret=%d", ret);
        return;
    } else {
        JLOG_INFO("%s Created inbound SRTP session", dtls_srtp->role == DTLS_SRTP_ROLE_SERVER ? "server" : "client");
    }

    // derive outbounds keys
	srtp_policy_t outbound = {};
	srtp_crypto_policy_set_from_profile_for_rtp(&outbound.rtp, srtpProfile);
	srtp_crypto_policy_set_from_profile_for_rtcp(&outbound.rtcp, srtpProfile);
	outbound.ssrc.type = ssrc_any_outbound;
	outbound.key = (dtls_srtp->role == DTLS_SRTP_ROLE_CLIENT) ? dtls_srtp->local_policy_key : dtls_srtp->remote_policy_key;
	outbound.window_size = 1024;
	outbound.allow_repeat_tx = true;
	outbound.next = NULL;

    dtls_srtp->local_policy = outbound;

    if ((ret = srtp_create(&dtls_srtp->srtp_out, &dtls_srtp->local_policy)) != srtp_err_status_ok) {
        JLOG_ERROR("Error creating outbound SRTP session, ret=%d", ret);
        return;
    } else {
        JLOG_INFO("%s Created outbound SRTP session", dtls_srtp->role == DTLS_SRTP_ROLE_SERVER ? "server" : "client");
    }
    dtls_srtp->state = DTLS_SRTP_STATE_CONNECTED;
}

static int dtls_srtp_do_handshake(dtls_srtp_t *dtls_srtp) {

    int ret;

    static mbedtls_timing_delay_context timer;

    mbedtls_ssl_set_timer_cb(&dtls_srtp->ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    mbedtls_ssl_set_export_keys_cb(&dtls_srtp->ssl, dtls_srtp_key_derivation, dtls_srtp);

    mbedtls_ssl_set_bio(&dtls_srtp->ssl, dtls_srtp, dtls_srtp->udp_send, dtls_srtp->udp_recv, NULL);

    do {

        ret = mbedtls_ssl_handshake(&dtls_srtp->ssl);

    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    return ret;
}

static int dtls_srtp_handshake_server(dtls_srtp_t *dtls_srtp) {

    int ret;

    while (1) {

        unsigned char client_ip[] = "test";

        mbedtls_ssl_session_reset(&dtls_srtp->ssl);

        mbedtls_ssl_set_client_transport_id(&dtls_srtp->ssl, client_ip, sizeof(client_ip));

        ret = dtls_srtp_do_handshake(dtls_srtp);

        if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {

            JLOG_DEBUG("DTLS hello verification requested");

        } else if (ret != 0) {

            JLOG_ERROR("failed! mbedtls_ssl_handshake returned -0x%.4x\n\n", (unsigned int)-ret);

            break;

        } else {

            break;
        }
    }

    if (ret == 0)
        JLOG_DEBUG("DTLS server handshake done");

    return ret;
}

static int dtls_srtp_handshake_client(dtls_srtp_t *dtls_srtp) {

    int ret;

    ret = dtls_srtp_do_handshake(dtls_srtp);

    if (ret != 0) {

        JLOG_ERROR("failed! mbedtls_ssl_handshake returned -0x%.4x\n\n", (unsigned int)-ret);
    }

    int flags;

    if ((flags = mbedtls_ssl_get_verify_result(&dtls_srtp->ssl)) != 0) {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        char vrfy_buf[512];
#endif

        JLOG_DEBUG(" failed\n");

#if !defined(MBEDTLS_X509_REMOVE_INFO)
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        JLOG_DEBUG("%s\n", vrfy_buf);
#endif
    }

    JLOG_DEBUG("DTLS client handshake done");

    return ret;
}

int dtls_srtp_handshake(dtls_srtp_t *dtls_srtp, addr_record_t *addr) {

    int ret;

    const mbedtls_x509_crt *remote_crt;

    dtls_srtp->remote_addr = addr;

    if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
        
        ret = dtls_srtp_handshake_server(dtls_srtp);

    } else {
        aos_msleep(1500);
        ret = dtls_srtp_handshake_client(dtls_srtp);
    }

    if ((remote_crt = mbedtls_ssl_get_peer_cert(&dtls_srtp->ssl)) != NULL) {

        dtls_srtp_x509_digest(remote_crt, dtls_srtp->remote_fingerprint);

        JLOG_DEBUG("remote fingerprint: %s", dtls_srtp->remote_fingerprint);

    } else {

        JLOG_ERROR("no remote fingerprint");
    }

    mbedtls_dtls_srtp_info dtls_srtp_negotiation_result;
    mbedtls_ssl_get_dtls_srtp_negotiation_result(&dtls_srtp->ssl, &dtls_srtp_negotiation_result);

    return ret;
}

void dtls_srtp_reset_session(dtls_srtp_t *dtls_srtp) {

    if (dtls_srtp->state == DTLS_SRTP_STATE_CONNECTED) {

        srtp_dealloc(dtls_srtp->srtp_in);
        srtp_dealloc(dtls_srtp->srtp_out);
        mbedtls_ssl_session_reset(&dtls_srtp->ssl);
    }

    dtls_srtp->state = DTLS_SRTP_STATE_INIT;
}

int dtls_srtp_write(dtls_srtp_t *dtls_srtp, const char *buf, size_t len) {

    int ret;

    do {

        ret = mbedtls_ssl_write(&dtls_srtp->ssl, (unsigned char *)buf, len);

    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    return ret;
}

int dtls_srtp_read(dtls_srtp_t *dtls_srtp, char *buf, size_t len) {

    int ret;

    memset(buf, 0, len);

    do {

        ret = mbedtls_ssl_read(&dtls_srtp->ssl, (unsigned char *)buf, len);

    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    return ret;
}

int dtls_srtp_validate(unsigned char *buf) {

    if (buf == NULL)
        return 0;

    return ((*buf >= 20) && (*buf <= 64));
}

int dtls_srtp_decrypt_rtp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes) {

    return srtp_unprotect(dtls_srtp->srtp_in, packet, bytes);
}

int dtls_srtp_decrypt_rtcp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes) {

    return srtp_unprotect_rtcp(dtls_srtp->srtp_in, packet, bytes);
}

int dtls_srtp_encrypt_rtp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes) {

    return srtp_protect(dtls_srtp->srtp_out, packet, bytes);
}

int dtls_srtp_encrypt_rctp_packet(dtls_srtp_t *dtls_srtp, void *packet, int *bytes) {

    return srtp_protect_rtcp(dtls_srtp->srtp_out, packet, bytes);
}

#if defined(CONFIG_LIBJUICE_USE_MBEDTLS) && defined(MBEDTLS_DEBUG_C)
void _ssl_debug(void *ctx, int level, const char *file, int line, const char *str) {
    static const char juice_level_map[5] = {JUICE_LOG_LEVEL_NONE, JUICE_LOG_LEVEL_ERROR, JUICE_LOG_LEVEL_WARN,
                                            JUICE_LOG_LEVEL_INFO, JUICE_LOG_LEVEL_DEBUG};
    juice_log_write(juice_level_map[level], file, line, str);
}
#endif

#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
static const char mbedtls_level_map[7] = {4, 4, 3, 2, 1, 1, 0};
static void mbedtls_log(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stdout, "Usage: %s [VERBOSE %d|DEBUG %d | INFO %d | WARN %d | ERROR %d | FATAL %d | NONE %d]",
		        argv[0], JUICE_LOG_LEVEL_VERBOSE, JUICE_LOG_LEVEL_DEBUG, JUICE_LOG_LEVEL_INFO,
		        JUICE_LOG_LEVEL_WARN, JUICE_LOG_LEVEL_ERROR, JUICE_LOG_LEVEL_FATAL, JUICE_LOG_LEVEL_NONE);
		fflush(stdout);
		return;
	}
    juice_log_level_t juice_level = atoi(argv[1]);
    mbedtls_debug_set_threshold(mbedtls_level_map[juice_level]);
}

ALIOS_CLI_CMD_REGISTER(mbedtls_log, mbedtls_log, mbedtls_log);

static void mbedtls_list_cs(int argc, char **argv) {
    const int *list;

    list = mbedtls_ssl_list_ciphersuites();
    while (*list) {
        JLOG_INFO(" %-42s", mbedtls_ssl_get_ciphersuite_name(*list));
        list++;
        if (!*list) {
            break;
        }
        JLOG_INFO(" %s\n", mbedtls_ssl_get_ciphersuite_name(*list));
        list++;
    }
    JLOG_INFO("\n");
}
ALIOS_CLI_CMD_REGISTER(mbedtls_list_cs, mbedtls_list_cs, mbedtls_list_cs);
#endif