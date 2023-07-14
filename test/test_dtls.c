#include "test_config.h"
#include "dtls_srtp.h"
#include "udp.h"
#include "log.h"

#define LOCAL_ADDRESS "192.168.4.2"
#define REMOTE_ADDRESS "192.168.4.2"

void test_handshake(char *role) {

    dtls_srtp_t dtls_srtp;
    udp_socket_config_t udp_socket_config;
    socket_t udp_socket;

    addr_record_t local_addr;
    addr_record_t remote_addr;

    if (strstr(role, "client")) {

        addr_resolve(LOCAL_ADDRESS, NULL, &local_addr, 1);
        addr_set_port((struct sockaddr *)&local_addr, 1234);
        JLOG_ADDR_RECORD(&local_addr);
        addr_resolve(REMOTE_ADDRESS, NULL, &remote_addr, 1);
        addr_set_port((struct sockaddr *)&remote_addr, 5677);
        JLOG_ADDR_RECORD(&remote_addr);

        udp_socket_config.bind_address = LOCAL_ADDRESS;
        udp_socket_config.port_begin = 1234;
        udp_socket_config.port_end = 1234;
        udp_socket = udp_create_socket(&udp_socket_config);
    
        dtls_srtp_init(&dtls_srtp, DTLS_SRTP_ROLE_CLIENT, &udp_socket);

    } else {
        JLOG_INFO("resolve: %s", LOCAL_ADDRESS);
        addr_resolve(LOCAL_ADDRESS, NULL, &local_addr, 1);
        addr_set_port((struct sockaddr *)&local_addr, 5677);
        JLOG_ADDR_RECORD(&local_addr);
        JLOG_INFO("resolve: %s", REMOTE_ADDRESS);
        addr_resolve(REMOTE_ADDRESS, NULL, &remote_addr, 1);
        addr_set_port((struct sockaddr *)&remote_addr, 1234);
        JLOG_ADDR_RECORD(&remote_addr);

        udp_socket_config.bind_address = LOCAL_ADDRESS;
        udp_socket_config.port_begin = 5677;
        udp_socket_config.port_end = 5677;
        udp_socket = udp_create_socket(&udp_socket_config);
    
        dtls_srtp_init(&dtls_srtp, DTLS_SRTP_ROLE_SERVER, &udp_socket);
    }
    
    JLOG_INFO("----------- %s handshake start -----------", role);
    dtls_srtp_handshake(&dtls_srtp, &remote_addr);
    JLOG_INFO("----------- %s handshake end -----------", role);

    unsigned char buf[64];

    memset(buf, 0, sizeof(buf));

    if (strstr(role, "client")) {

        snprintf((void *)buf, sizeof(buf), "hello from client");

        JLOG_VERBOSE("client sending: %s\n", buf);

        usleep(100 * 1000);

        dtls_srtp_write(&dtls_srtp, buf, sizeof(buf));

        dtls_srtp_read(&dtls_srtp, buf, sizeof(buf));

        JLOG_VERBOSE("client received: %s\n", buf);

    } else {

        dtls_srtp_read(&dtls_srtp, buf, sizeof(buf));

        JLOG_VERBOSE("server received: %s\n", buf);

        snprintf((void *)buf, sizeof(buf), "hello from server");

        JLOG_VERBOSE("server sending: %s\n", buf);

        usleep(100 * 1000);

        dtls_srtp_write(&dtls_srtp, buf, sizeof(buf));
    }

    dtls_srtp_deinit(&dtls_srtp);
}

void test_reset(void *param) {
    JLOG_INFO("----------reset------------");
    dtls_srtp_t dtls_srtp;
    dtls_srtp_init(&dtls_srtp, DTLS_SRTP_ROLE_CLIENT, NULL);
    dtls_srtp_deinit(&dtls_srtp);
}

void test_dtls_entry(void *param) {
    test_handshake(param);
}

#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
#include <aos/kernel.h>

static void test_dtls(int argc, char **argv) {

    if (argc < 2) {
        JLOG_VERBOSE("Usage: %s client/server\n", argv[0]);
        return;
    }

    if (strstr(argv[1], "client")) {
        aos_task_new("dtls_client", test_dtls_entry, "client", 500 * 1024);
    } else if (strstr(argv[1], "server")) {
        aos_task_new("dtls_server", test_dtls_entry, "server", 500 * 1024);
    } else if (strstr(argv[1], "reset")) {
        aos_task_new("dtls_reset", test_dtls_entry, "reset", 500 * 1024);
    }
}

ALIOS_CLI_CMD_REGISTER(test_dtls, test_dtls, test_dtls);
#endif