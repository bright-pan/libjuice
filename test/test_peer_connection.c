#include "test_config.h"
#include "peer_connection.h"
#include "udp.h"
#include "log.h"

peer_connection_t pc_server, pc_client;
peer_options_t server_options, client_options;

static void test_pc_entry(void *param) {

  peer_options_set_default(&server_options, 55000, 56000);
  peer_connection_configure(&pc_server, "peer_server", &server_options);

  peer_options_set_default(&client_options, 57000, 58000);
  peer_connection_configure(&pc_client, "peer_client", &client_options);
  

}

#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
#include <aos/kernel.h>

static void test_pc(int argc, char **argv) {

    if (argc < 2) {
        JLOG_VERBOSE("Usage: %s client/server\n", argv[0]);
        return;
    }

    if (strstr(argv[1], "client")) {
        aos_task_new("pc_client", test_pc_entry, "client", 500 * 1024);
    } else if (strstr(argv[1], "server")) {
        aos_task_new("pc_server", test_pc_entry, "server", 500 * 1024);
    } else if (strstr(argv[1], "reset")) {
        // aos_task_new("dtls_reset", test_pc_entry, "reset", 500 * 1024);
    }
}

ALIOS_CLI_CMD_REGISTER(test_pc, test_pc, test_pc);
#endif