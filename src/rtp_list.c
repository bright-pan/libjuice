#include "rtp_list.h"
#include "log.h"


static int by_seq(const rtp_frame_t *a, const rtp_frame_t *b)
{
    return (a->key.seq - b->key.seq);
}

static int by_bytes(const rtp_frame_t *a, const rtp_frame_t *b)
{
    return (a->bytes - b->bytes);
}

rtp_frame_t *rtp_frame_malloc(uint32_t ssrc, int seq, const char *packet, int bytes) {
    rtp_frame_t *frame = NULL;

    frame = (rtp_frame_t *)uthash_malloc(sizeof(rtp_frame_t));
    if (frame) {
        frame->key.seq = seq;
        frame->key.ssrc = ssrc;
        frame->bytes = bytes;
        frame->send_flag = 0;
        frame->timeout_count = RTP_FRAME_TIMEOUT_COUNT - 1;
        frame->packet = uthash_malloc(bytes);
        if (frame->packet) {
            memcpy(frame->packet, packet, bytes);
        } else {
            uthash_free(frame, 0);
            frame = NULL;
        }
    }
    return frame;
}

void rtp_frame_free(rtp_frame_t *frame) {
    if (frame) {
        uthash_free(frame->packet, 0);
        uthash_free(frame, 0);
    }
}

void rtp_list_init(rtp_list_t *rtp_list) {
    rtp_list->utlist = NULL;
    rwlock_init(&rtp_list->rwlock);
}

void rtp_list_rlock(rtp_list_t *rtp_list) {
    rwlock_rlock(&rtp_list->rwlock);
}

void rtp_list_wlock(rtp_list_t *rtp_list) {
    rwlock_wlock(&rtp_list->rwlock);
}

void rtp_list_unlock(rtp_list_t *rtp_list) {
    rwlock_unlock(&rtp_list->rwlock);
}

rtp_frame_t *rtp_list_find_by_key(rtp_list_t *rtp_list, rtp_frame_key_t key) {
    rtp_frame_t l, *s;

    memset(&l, 0, sizeof(rtp_frame_t));
    l.key = key;
    HASH_FIND(hh, rtp_list->utlist, &l.key, sizeof(rtp_frame_key_t), s);  /* seq already in the hash? */
    return s;
}

int rtp_list_insert_ex(rtp_list_t *rtp_list, rtp_frame_t *frame, int size) {
    int ret = -1;
    rtp_frame_t *s;

    if (frame && (HASH_COUNT(rtp_list->utlist) <= size)) {
        s = rtp_list_find_by_key(rtp_list, frame->key); /* seq already in the hash? */
        if (s == NULL) {
            // HASH_ADD(seq, s);  /* seq is the key field */
            HASH_ADD(hh, rtp_list->utlist, key, sizeof(rtp_frame_key_t), frame);
            ret = 0;
        }
    }
    return ret;
}

// int rtp_list_insert(rtp_list_t *rtp_list, rtp_frame_t *frame) {
//     return rtp_list_insert_ex(rtp_list, frame, rtp_list_MAX_SIZE);
// }

void rtp_list_pop(rtp_list_t *rtp_list, rtp_frame_t *frame) {
    if (frame) {
        HASH_DEL(rtp_list->utlist, frame);  /* frame: pointer to delete */
    }
}

// rtp_frame_t *rtp_list_find_by_key(rtp_list_t *rtp_list, rtp_frame_key_t key) {
//     rtp_frame_t l, *s;

//     memset(&l, 0, sizeof(rtp_frame_t));
//     l.key = key;
//     HASH_FIND(hh, rtp_list->utlist, &l.key, sizeof(rtp_frame_key_t), s);  /* seq already in the hash? */
//     return s;
// }

void rtp_list_delete(rtp_list_t *rtp_list, rtp_frame_t *frame) {
    if (frame) {
        HASH_DEL(rtp_list->utlist, frame);  /* frame: pointer to delete */
        rtp_frame_free(frame);
    }
}

void rtp_list_delete_all(rtp_list_t *rtp_list) {
    rtp_frame_t *frame;
    rtp_frame_t *tmp;

    HASH_ITER(hh, rtp_list->utlist, frame, tmp) {
        rtp_list_delete(rtp_list, frame);  /* delete it (users advances to next) */
    }
}

void rtp_list_reset(rtp_list_t *rtp_list) {
    rtp_list_delete_all(rtp_list);
}

int rtp_list_delete_by_key(rtp_list_t *rtp_list, rtp_frame_key_t key) {
    int ret = -1;
    rtp_frame_t *frame;

    frame = rtp_list_find_by_key(rtp_list, key);
    if (frame) {
        rtp_list_delete(rtp_list, frame);
        ret = 0;
    }
    return ret;
}

int rtp_list_count(rtp_list_t *rtp_list) {
    return HASH_COUNT(rtp_list->utlist);
}

void rtp_list_sort_by_bytes(rtp_list_t *rtp_list) {
    HASH_SORT(rtp_list->utlist, by_bytes);
}

void rtp_list_sort_by_seq(rtp_list_t *rtp_list) {
    HASH_SORT(rtp_list->utlist, by_seq);
}

static void rtp_frame_print(rtp_frame_t *frame, int dump_hex_flag) {
    if (frame) {
        JLOG_INFO("----------------------------");
        if (dump_hex_flag) {
            JLOG_INFO_DUMP_HEX(frame->packet, frame->bytes, "key: %d, %d: %d Bytes", frame->key.ssrc, frame->key.seq, frame->bytes);
        } else {
            JLOG_INFO("key: %d, %d: %d Bytes", frame->key.ssrc, frame->key.seq, frame->bytes);
        }
    }
}

void rtp_list_print_by_key(rtp_list_t *rtp_list, rtp_frame_key_t key, int dump_hex_flag) {
    rtp_frame_t *frame;
    frame = rtp_list_find_by_key(rtp_list, key);
    if (frame) {
        rtp_frame_print(frame, dump_hex_flag);
    }
}

void rtp_list_print_all(rtp_list_t *rtp_list, int dump_hex_flag) {
    rtp_frame_t *frame;

    JLOG_INFO("rtp frame counts[%d]", rtp_list_count(rtp_list));
    for (frame = rtp_list->utlist; frame != NULL; frame = (rtp_frame_t *)(frame->hh.next)) {
        rtp_frame_print(frame, dump_hex_flag);
    }
}

#if 1
#include <aos/cli.h>
#include <aos/kernel.h>


int test_rtplist(int argc, char **argv) {
    static rtp_list_t test_list;
    static int id = 1;
    rtp_frame_t *s;
    rtp_frame_key_t key;
    int temp;
    if (argc < 2) {
        printf("%s 0 - list initial\n", argv[0]);
        printf("%s 1 ssrc frame size - add frame size\n", argv[0]);
        printf("%s 2 ssrc seq frame size - add or rename frame by id\n", argv[0]);
        printf("%s 3 ssrc seq - find frame\n", argv[0]);
        printf("%s 4 ssrc seq - delete frame\n", argv[0]);
        printf("%s 5 - delete all\n", argv[0]);
        printf("%s 6 - sort items by bytes\n", argv[0]);
        printf("%s 7 - sort items by id\n", argv[0]);
        printf("%s 8 - print all\n", argv[0]);
        printf("%s 9 - count list\n", argv[0]);
    } else {
        switch (atoi(argv[1])) {
            case 0:
                rtp_list_init(&test_list);
                break;
            case 1:
                s = rtp_frame_malloc(atoi(argv[2]), id++, argv[3], atoi(argv[4]));
                rtp_list_insert(&test_list, s);
                break;
            case 2:
                s = rtp_frame_malloc(atoi(argv[2]), atoi(argv[3]), argv[4], atoi(argv[5]));
                rtp_list_insert(&test_list, s);
                break;
            case 3:
                key.ssrc = atoi(argv[2]);
                key.seq = atoi(argv[3]);
                s = rtp_list_find_by_key(&test_list, key);
                printf("ssrc: %d, seq: %d, packet: %s\n", key.ssrc, key.seq, s ? s->packet : "unknown");
                break;
            case 4:
                key.ssrc = atoi(argv[2]);
                key.seq = atoi(argv[3]);
                s = rtp_list_find_by_key(&test_list, key);
                if (s) {
                    rtp_list_delete(&test_list, s);
                } else {
                    printf("key[%d:%d] unknown\n", key.ssrc, key.seq);
                }
                break;
            case 5:
                rtp_list_delete_all(&test_list);
                break;
            case 6:
                rtp_list_sort_by_bytes(&test_list);
                break;
            case 7:
                rtp_list_sort_by_seq(&test_list);
                break;
            case 8:
                rtp_list_print_all(&test_list, 1);
                break;
            case 9:
                temp = rtp_list_count(&test_list);
                printf("there are %d frame\n", temp);
                break;
        }
    }
    return 0;
}

ALIOS_CLI_CMD_REGISTER(test_rtplist, test_rtplist, test_rtplist);

#endif
