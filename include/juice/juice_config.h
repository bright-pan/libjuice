#ifndef __JUICE_CONFIG__
#define __JUICE_CONFIG__

#include "juice.h"
#include <aos/debug.h>

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


#define MQTT_THREAD_STACK_SIZE 50000
#define MQTT_CLIENT_BUF_SIZE SDP_CONTENT_LENGTH

#define MQTT_URI                "tcp://broker.emqx.io:1883"
// #define MQTT_URI                "tcp://192.168.12.193:1883"
#define MQTT_SUBTOPIC           "/webrtc/mqttjs_bd853a81"
#define MQTT_PUBTOPIC           "/webrtc/mqttjs_3f770906"
#define MQTT_WILLMSG            "Goodbye!"
#define MQTT_WILLFLAG           0


#define SCTP_MTU (1200)
#define CONFIG_MTU SCTP_MTU

#define VIDEO_RB_DATA_LENGTH (CONFIG_MTU * 64)
#define AUDIO_RB_DATA_LENGTH (CONFIG_MTU * 64)
#define DATA_RB_DATA_LENGTH (SCTP_MTU * 64)

#if defined(JUICE_USE_MEMPOOL)
#include "mempool.h"

#define juice_malloc(size)       MEMPOOL_MALLOC(SRAM_RTMP, size)
#define juice_free(ptr)          MEMPOOL_FREE(ptr)
#define juice_calloc(n, size)    MEMPOOL_MALLOC(SRAM_RTMP, (n) * (size))
#define juice_realloc(ptr, size) MEMPOOL_REALLOC(SRAM_RTMP, ptr, size)
#else
#define juice_malloc(size)       malloc(size)
#define juice_free(ptr)          free(ptr)
#define juice_calloc(n, size)    calloc(n, size)
#define juice_realloc(ptr, size) realloc(ptr, size)
#endif

#define juice_assert(ptr)        aos_assert(ptr)


#define RTP_FRAME_INTERVAL 5 //1000/30)
#define RTP_FRAME_TIMEOUT 1500
#define RTP_FRAME_TIMEOUT_COUNT (RTP_FRAME_TIMEOUT / RTP_FRAME_INTERVAL)
#define RTP_FRAME_RESEND_COUNT 3

// posix thread
#if defined(__linux__) || defined(AOS_COMP_POSIX)

#include <pthread.h>
#define THREAD_DEFAULT_STACK_SIZE       (40 * 1024)
#define THREAD_DEFAULT_PRIORITY         30
#define THREAD_DEFAULT_SLICE            10
#define THREAD_CREATE_JOINABLE          PTHREAD_CREATE_JOINABLE
#define THREAD_SCOPE_SYSTEM             PTHREAD_SCOPE_SYSTEM
#define THREAD_EXPLICIT_SCHED           PTHREAD_EXPLICIT_SCHED
#define THREAD_DEFAULT_GUARD_SIZE       256
#define THREAD_DYN_INIT                 PTHREAD_DYN_INIT
#endif

#endif