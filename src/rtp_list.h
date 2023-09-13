#ifndef __RTP_FRAME_H__
#define __RTP_FRAME_H__

#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdio.h>   /* printf */
#include <stdlib.h>  /* atoi, malloc */
#include <string.h>  /* strcpy */
#include "thread.h"
#include "uthash.h"

/* undefine the defaults */
#undef uthash_malloc
#undef uthash_free

/* re-define, specifying alternate functions */
#define uthash_malloc(sz) juice_malloc(sz)
#define uthash_free(ptr, sz) juice_free(ptr)

typedef struct {
    int seq;
    uint32_t ssrc;
} rtp_frame_key_t;

typedef struct {
    rtp_frame_key_t key;                    /* key */
    char *packet;
    int bytes;
    int timeout_count;
    int send_flag;
    int type;
    UT_hash_handle hh;         /* makes this structure hashable */
} rtp_frame_t;

typedef struct {
    rtp_frame_t *utlist;
    rwlock_t rwlock;
} rtp_list_t;

rtp_frame_t *rtp_frame_malloc(int type, uint32_t ssrc, int seq, void *packet, int bytes);
void rtp_frame_free(rtp_frame_t *frame);

void rtp_list_init(rtp_list_t *rtp_list);
void rtp_list_rlock(rtp_list_t *rtp_list);
void rtp_list_wlock(rtp_list_t *rtp_list);
void rtp_list_unlock(rtp_list_t *rtp_list);

int rtp_list_insert_ex(rtp_list_t *rtp_list, rtp_frame_t *frame, int size);
#define rtp_list_insert(list, frame) rtp_list_insert_ex(list, frame, RTP_LIST_MAX_SIZE)
int rtp_list_insert_packet(rtp_list_t *insert_list, void *packet, int bytes);
void rtp_list_pop(rtp_list_t *rtp_list, rtp_frame_t *frame);
rtp_frame_t *rtp_list_find_by_key(rtp_list_t *rtp_list, rtp_frame_key_t key);
void rtp_list_delete(rtp_list_t *rtp_list, rtp_frame_t *frame);
void rtp_list_delete_all(rtp_list_t *rtp_list);
void rtp_list_reset(rtp_list_t *rtp_list);
int rtp_list_delete_by_key(rtp_list_t *rtp_list, rtp_frame_key_t key);
int rtp_list_count(rtp_list_t *rtp_list);
void rtp_list_sort_by_bytes(rtp_list_t *rtp_list);
void rtp_list_sort_by_key(rtp_list_t *rtp_list);
void rtp_list_print_all(rtp_list_t *rtp_list, int dump_hex_flag);
void rtp_list_print_by_key(rtp_list_t *rtp_list, rtp_frame_key_t key, int dump_hex_flag);

#endif