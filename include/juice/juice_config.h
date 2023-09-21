#ifndef __JUICE_CONFIG__
#define __JUICE_CONFIG__

#include "juice.h"
#include <aos/debug.h>
#include "codec.h"

// posix thread
#if defined(__linux__) || defined(AOS_COMP_POSIX)
#include <pthread.h>
#define THREAD_DEFAULT_STACK_SIZE       (40 * 1024)
#define THREAD_DEFAULT_PRIORITY         33 // 62-32=30
#define THREAD_DEFAULT_SLICE            10
#define THREAD_CREATE_JOINABLE          PTHREAD_CREATE_JOINABLE
#define THREAD_SCOPE_SYSTEM             PTHREAD_SCOPE_SYSTEM
#define THREAD_EXPLICIT_SCHED           PTHREAD_EXPLICIT_SCHED
#define THREAD_DEFAULT_GUARD_SIZE       256
#define THREAD_DYN_INIT                 PTHREAD_DYN_INIT
#endif

#define BUFFER_SIZE 4096
#define BIND_ADDRESS "192.168.4.2"

#define SERVER_BIND_ADDRESS "192.168.4.2"
#define SERVER_BIND_PORT 3478

// #define STUN_SERVER_HOST "test.funlink.cloud"
#define STUN_SERVER_HOST "192.168.1.186"
#define STUN_SERVER_PORT 3478

// #define TURN_SERVER_HOST "test.funlink.cloud"
#define TURN_SERVER_HOST "192.168.1.186"
#define TURN_SERVER_PORT 3478
#define TURN_SERVER_USERNAME "username1"
#define TURN_SERVER_PASSWORD "password1"

// #define TURN_SERVER_HOST "a.relay.metered.ca"
// #define TURN_SERVER_PORT 80
// #define TURN_SERVER_USERNAME "582e76da4d1dca59a632a28c"
// #define TURN_SERVER_PASSWORD "8spay3NSF+9uslHA"

#define MQTT_THREAD_NAME "mqtt_sdp"
#define MQTT_THREAD_PRIORITY THREAD_DEFAULT_PRIORITY - 2;
#define MQTT_THREAD_STACK_SIZE 50000
#define MQTT_CLIENT_BUF_SIZE SDP_CONTENT_LENGTH

#define MQTT_URI                "tcp://122.114.60.74:1883"
// #define MQTT_URI                "tcp://mqtt.eclipseprojects.io:1883"
// #define MQTT_URI                "tcp://192.168.12.193:1883"
#define MQTT_USERNAME           "nanmu0001"
#define MQTT_PASSWORD           "nanmu0001!@#$%"
#define MQTT_CLIENTID           "D_1V1_SWQ00001_1V1_00:FF:AF:CD:97:21"
#define MQTT_SUBTOPIC           "/webrtc/D_1V1_SWQ00001_1V1_00:FF:AF:CD:97:21"
#define MQTT_PUBTOPIC           "/webrtc/W_1V1_SWQ00001_1V1_00:FF:AF:CD:97:21"
#define MQTT_WILLMSG            "Goodbye!"
#define MQTT_WILLFLAG           0


#define SCTP_MTU (1200)
#define CONFIG_MTU SCTP_MTU

#define VIDEO_RB_DATA_LENGTH (CONFIG_MTU * 64)
#define AUDIO_RB_DATA_LENGTH (CONFIG_MTU * 64)
#define DATA_RB_DATA_LENGTH (SCTP_MTU * 64)

#if defined(JUICE_USE_MEMPOOL)
#include "mempool.h"

#define SRAM_JUICE SRAM_RTMP

#define juice_malloc(size)       MEMPOOL_MALLOC(SRAM_JUICE, size)
#define juice_free(ptr)          do { \
    if (ptr) MEMPOOL_FREE(ptr); \
} while(0)
#define juice_calloc(n, size)    MEMPOOL_CALLOC(SRAM_JUICE, n, size)
#define juice_realloc(ptr, size) MEMPOOL_REALLOC(SRAM_JUICE, ptr, size)
#else
#define juice_malloc(size)       malloc(size)
#define juice_free(ptr)          free(ptr)
#define juice_calloc(n, size)    calloc(n, size)
#define juice_realloc(ptr, size) realloc(ptr, size)
#endif

#define juice_assert(ptr)        aos_assert(ptr)


#define RTP_TX_CACHE_TIMEOUT_CHECK 300 //1000/30)
#define RTP_TX_CACHE_TIMEOUT 1500

#define RTP_TX_CACHE_LIST_MAX_SIZE 256
#define RTP_RTX_CACHE_LIST_MAX_SIZE (RTP_TX_CACHE_LIST_MAX_SIZE / 4)
#define RTP_RECV_CACHE_LIST_MAX_SIZE 128
#define RTCP_PSFB_PLI_PROCESS_INTERVAL 1000
// #define RTP_FRAME_RESEND_COUNT 3

#define PEER_CONNECTION_VIDEO_CODEC MEDIA_CODEC_H264;
#define PEER_CONNECTION_VIDEO_RTX_CODEC MEDIA_CODEC_H264_RTX;
#define PEER_CONNECTION_AUDIO_CODEC MEDIA_CODEC_PCMA;
#define PEER_CONNECTION_DATA_CHANNEL 0
#endif