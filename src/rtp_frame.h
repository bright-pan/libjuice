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
    int seq;                    /* key */
    char *packet;
    int bytes;
    int timeout_count;
    int resend_count;
    UT_hash_handle hh;         /* makes this structure hashable */
} rtp_frame_t;

rtp_frame_t *rtp_frame_malloc(int seq, const char *packet, int bytes);
void rtp_frame_free(rtp_frame_t *frame);

int rtp_frame_list_insert(rtp_frame_t **rtp_frame_list, rtp_frame_t *frame);
void rtp_frame_list_pop(rtp_frame_t **rtp_frame_list, rtp_frame_t *frame);
rtp_frame_t *rtp_frame_list_find_by_seq(rtp_frame_t **rtp_frame_list, int seq_number);
void rtp_frame_list_delete(rtp_frame_t **rtp_frame_list, rtp_frame_t *frame);
void rtp_frame_list_delete_all(rtp_frame_t **rtp_frame_list);
void rtp_frame_list_reset(rtp_frame_t **rtp_frame_list);
int rtp_frame_list_delete_by_seq_number(rtp_frame_t **rtp_frame_list, int seq_number);
int rtp_frame_list_count(rtp_frame_t **rtp_frame_list);
void rtp_frame_list_sort_by_bytes(rtp_frame_t **rtp_frame_list);
void rtp_frame_list_sort_by_seq_number(rtp_frame_t **rtp_frame_list);
void rtp_frame_list_print_all(rtp_frame_t **rtp_frame_list);
void rtp_frame_list_print_by_seq_number(rtp_frame_t **rtp_frame_list, int seq_number);

#endif