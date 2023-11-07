#include <cJSON.h>
#include <string.h>
#include "socket.h"
#include "thread.h"
#include "udp.h"
#include "peer_connection.h"
#include "log.h"

#define PIPE_LOCAL_ADDR "192.168.4.2"
#define PIPE_LOCAL_PORT (6666UL)

#define PIPE_REMOTE_ADDR "192.168.4.1"
#define PIPE_REMOTE_PORT (7777UL)

#define PIPE_BUFF_SIZE 2048

// static struct sockaddr_in pipe_addr;
static thread_t pipe_thread;
static addr_record_t pipe_local_addr;
static addr_record_t pipe_remote_addr;
static int pipe_sockfd = -1;
static int pipe_connected = 0;
static char pipe_buffer[PIPE_BUFF_SIZE];
static char *pipe_json_connect = "{\"type\":\"pipe\",\"req\":\"connect\"}";

int pipe_send(char *buf, int size) {
    int ret = -1;
    if (pipe_connected) {
        ret = juice_udp_sendto(pipe_sockfd, buf, size, &pipe_remote_addr);
    } else {
        JLOG_ERROR("funlink_pipe is not connect!\n");
    }
    return ret;
}

int pipe_thread_recv(socket_t sock, char *buffer, size_t size, addr_record_t *src) {
	JLOG_VERBOSE("Receiving datagram");
	int len;
	while ((len = udp_recvfrom(sock, buffer, size, src)) == 0) {
		// Empty datagram (used to interrupt)
	}

	if (len < 0) {
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK || sockerrno == SEBUSY) {
			JLOG_VERBOSE("No more datagrams to receive");
			return 0;
		}
		JLOG_ERROR("recvfrom failed, errno=%d, %s", sockerrno, sock_strerr(sockerrno));
		return -1;
	}

	addr_unmap_inet6_v4mapped((struct sockaddr *)&src->addr, &src->len);
	return len; // len > 0
}

void pipe_recv_process(peer_connection_t *pc, char *buf, size_t size, addr_record_t *src) {
    JLOG_INFO("recvfrom: %d", size);
    JLOG_ADDR_RECORD(src);
    // strncpy(pipe_buffer, (char *)msg_data->message->payload, SDP_CONTENT_LENGTH);
    cJSON *cmd = cJSON_Parse(buf);
    if (cmd) {
        char *cmd_type = cJSON_GetObjectItem(cmd, "type")->valuestring;
        if (cmd_type) {
            JLOG_INFO("type: %s", cmd_type);
            if (strstr(cmd_type,"offer")) {
                char *sdp_string = cJSON_GetObjectItem(cmd, "sdp")->valuestring;
                if (sdp_string) {
                    // JLOG_INFO("%s", sdp_string);
                    if (pc) {
                        juice_set_remote_description(pc->juice_agent, sdp_string);
                        // answer
                        // STATE_CHANGED(pc, PEER_CONNECTION_START);
                    }
                }
                cJSON *payload = cJSON_GetObjectItem(cmd, "payload");
                if (payload) {
                    cJSON *video = cJSON_GetObjectItem(payload, "video");
                    if (video) {
                        peer_connection_set_video_payload(pc, video->valueint);
                    }
                    cJSON *audio = cJSON_GetObjectItem(payload, "audio");
                    if (audio) {
                        peer_connection_set_audio_payload(pc, audio->valueint);
                    }
                }
            }
            if (strstr(cmd_type,"candidate")) {
                char *candidate_string = cJSON_GetObjectItem(cmd, "candidate")->valuestring;
                if (candidate_string) {
                    JLOG_INFO("%s", candidate_string);
                    if (pc) {
                        juice_add_remote_candidate(pc->juice_agent, candidate_string);
                    }
                }
            }
            if (strstr(cmd_type,"pipe")) {
                char *resp_string = cJSON_GetObjectItem(cmd, "resp")->valuestring;
                if (resp_string) {
                    JLOG_INFO("%s", resp_string);
                    if (0 == strncmp(resp_string, "connected", strlen("connected"))) {
                        JLOG_INFO("pipe connected");
                        pipe_connected = 1;
                    } else {
                        JLOG_ERROR("pipe not connected");
                    }
                }
            }
        }
    }
}

static void *pipe_thread_entry(void *param) {
    int ret = 0;
    int len;
	struct pollfd pfd[1];
    udp_socket_config_t pipe_socket_config;
    addr_record_t src;
    peer_connection_t *pc = param;

    JLOG_INFO("pipe local: %s", PIPE_LOCAL_ADDR);
    addr_resolve(PIPE_LOCAL_ADDR, NULL, &pipe_local_addr, 1);
    addr_set_port((struct sockaddr *)&pipe_local_addr, PIPE_LOCAL_PORT);
    JLOG_ADDR_RECORD(&pipe_local_addr);

    JLOG_INFO("pipe remote: %s", PIPE_REMOTE_ADDR);
    addr_resolve(PIPE_REMOTE_ADDR, NULL, &pipe_remote_addr, 1);
    addr_set_port((struct sockaddr *)&pipe_remote_addr, PIPE_REMOTE_PORT);
    JLOG_ADDR_RECORD(&pipe_remote_addr);

    //创建数据包套接字(UDP)
    pipe_socket_config.bind_address = PIPE_LOCAL_ADDR;
    pipe_socket_config.port_begin = PIPE_LOCAL_PORT;
    pipe_socket_config.port_end = PIPE_LOCAL_PORT;
    pipe_sockfd = udp_create_socket(&pipe_socket_config);
    if (pipe_sockfd < 0)
    {
        JLOG_ERROR("Socket error\n");
        goto __exit;
    }

    // pipe connect
    pfd[0].fd = pipe_sockfd;
	pfd[0].events = POLLIN;

    juice_udp_sendto(pipe_sockfd, pipe_json_connect, strlen(pipe_json_connect), &pipe_remote_addr);
    
    timediff_t timediff = 1000;

    thread_set_name_self("pipe_thread");

    while (1) {
        int ret = poll(pfd, 1, (int)timediff);
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				JLOG_VERBOSE("poll interrupted");
				continue;
			} else {
				JLOG_FATAL("poll failed, errno=%d, %s", sockerrno, sock_strerr(sockerrno));
				break;
			}
		}

        if (pfd->revents & POLLIN) {
            while ((len = pipe_thread_recv(pipe_sockfd, pipe_buffer, PIPE_BUFF_SIZE, &src)) > 0) {
                // mutex_unlock(&conn_impl->mutex);
                pipe_recv_process(pc, pipe_buffer, (size_t)len, &src);
            }
        }
    }

__exit:
    pthread_exit(&ret);
    return NULL;
}

static int pipe_init(thread_entry_t thread_entry, void *param) {
    int ret = -1;
    thread_attr_t attr;

    thread_attr_init(&attr, THREAD_DEFAULT_PRIORITY - 1, 20*1024);
    ret = thread_init_ex(&pipe_thread, &attr, thread_entry, param);
    if (ret != 0) {
        JLOG_ERROR("pipe thread created failure!");
    } else {
        JLOG_INFO("pipe thread created!");
    }
    return ret;
}

void pipe_create(char *name, void *param) {
    pipe_init(pipe_thread_entry, param);
}

#if 0
#include <aos/cli.h>

static void pipe_client_send(int argc, char **argv) {
    int ret;
    addr_record_t dst_addr;

    JLOG_INFO("dst addr: %s", argv[0]);
    addr_resolve(argv[0], NULL, &dst_addr, 1);
    addr_set_port((struct sockaddr *)&dst_addr, atoi(argv[1]));
    JLOG_ADDR_RECORD(&dst_addr);

    if (pipe_sockfd) {
        ret = juice_udp_sendto(pipe_sockfd, argv[2], strlen(argv[2]), &dst_addr);
        JLOG_ADDR_RECORD(&dst_addr);
        JLOG_INFO("sendto %s, ret=%d", argv[0], atoi(argv[1]), argv[2], ret);
    } else {
        JLOG_ERROR("pipe_sockfd is not created!");
    }
}

static void pipe_client(int argc, char **argv) {
    if (argc < 2) {
        JLOG_ERROR("Usage: %s start/[send ip port content]\n", argv[0]);
        return;
    }
    if (strstr(argv[1], "start")) {
        pipe_create("pipe_client", NULL);
    } else if (strstr(argv[1],"send")) {
        pipe_client_send(argc, &argv[2]);
    } else {
        JLOG_ERROR("Usage: %s start/[send ip port content]\n", argv[0]);
    }
}
ALIOS_CLI_CMD_REGISTER(pipe_client, pipe_client, pipe_client);

#endif