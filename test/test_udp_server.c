#include <aos/aos.h>
#include <aos/kernel.h>
#include <lwip/opt.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/api.h>
#include <string.h>

// configure log
#define CONFIG_LANGO_DBG_LEVEL LANGO_DBG_LOG
#define LANGO_DBG_TAG "UDP/S"
#include "lango_log.h"
// ------------------

#define LOCAL_PORT (7777UL)
#define BUFF_SIZE (256UL)

static int sockfd;

static void udp_task_entry(void *param) {
    int n, i, ret;
    char ReadBuff[BUFF_SIZE];
    struct sockaddr_in local_addr, remote_addr;
    socklen_t remote_addr_len;

    //创建数据包套接字(UDP)
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LANGO_LOG_ERR("Socket error\n");
    }
    //填充地址信息
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    //绑定socket
    ret = bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    LANGO_LOG_INFO("bind: %s:%d, ret=%d", inet_ntoa(local_addr.sin_addr.s_addr), LOCAL_PORT, ret);
    remote_addr_len = sizeof(remote_addr);

    while (1) {
        //等待客户端发送数据
        n = recvfrom(sockfd, ReadBuff, BUFF_SIZE, 0,
                     (struct sockaddr *)&remote_addr, &remote_addr_len);
        LANGO_LOG_INFO("recvfrom: %s:%d", inet_ntoa(remote_addr.sin_addr.s_addr), remote_addr.sin_port);
        LANGO_LOG_INFO_DUMP_HEX("context: ", ReadBuff, n);
    }
}

static void udp_sendto(int argc, char **argv) {
    int ret;
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len;

    if (sockfd) {
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = inet_addr(argv[0]);
        remote_addr.sin_port = htons(atoi(argv[1]));
        remote_addr_len = sizeof(remote_addr);
        ret = sendto(sockfd, argv[2], strlen(argv[2]), 0,(struct sockaddr *)&remote_addr,remote_addr_len);
        LANGO_LOG_INFO("sendto %s:%d, %s, ret=%d", argv[0], atoi(argv[1]), argv[2], ret);
    } else {
        LANGO_LOG_ERR("sockfd is not created!");
    }
}


static void udp_server(int argc, char **argv) {
    if (argc < 2) {
        LANGO_LOG_ERR("Usage: %s start/[send ip port content]\n", argv[0]);
        return;
    }
    if (strstr(argv[1], "start")) {
        aos_task_new("udp_server", udp_task_entry,  NULL, 10*1024);
    } else if (strstr(argv[1],"send")) {
        udp_sendto(argc, &argv[2]);
    } else {
        LANGO_LOG_ERR("Usage: %s start/[send ip port content]\n", argv[0]);
    }
}

ALIOS_CLI_CMD_REGISTER(udp_server, udp_server, udp_server);