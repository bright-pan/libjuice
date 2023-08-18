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
#include "uthash.h"

/* undefine the defaults */
#undef uthash_malloc
#undef uthash_free

/* re-define, specifying alternate functions */
#define uthash_malloc(sz) juice_malloc(sz)
#define uthash_free(ptr, sz) juice_free(ptr)

typedef struct {
    int seq_number;                    /* key */
    char *packet;
    int bytes;
    int count;
    UT_hash_handle hh;         /* makes this structure hashable */
} rtp_frame_t;

int rtp_frame_add(int seq_number, const char *packet, int bytes);
rtp_frame_t *rtp_frame_find(int seq_number);
void rtp_frame_delete(rtp_frame_t *frame);
void rtp_frame_delete_all(void);
void rtp_frame_reset(void);
int rtp_frame_delete_by_seq_number(int seq_number);
int rtp_frame_count(void);
void rtp_frame_sort_by_bytes(void);
void rtp_frame_sort_by_seq_number(void);
void rtp_frame_print_all(void);
void rtp_frame_print_by_seq_number(int seq_number);
int rt_frame_delete_timer_init(int interval);

#endif