#include "rtp_frame.h"
#include "aos/kernel.h"
#include "log.h"


// static rtp_frame_t **rtp_frame_list = NULL;


static int by_seq(const rtp_frame_t *a, const rtp_frame_t *b)
{
    return (a->seq - b->seq);
}

static int by_bytes(const rtp_frame_t *a, const rtp_frame_t *b)
{
    return (a->bytes - b->bytes);
}

rtp_frame_t *rtp_frame_malloc(int seq, const char *packet, int bytes) {
    rtp_frame_t *frame = NULL;

    frame = (rtp_frame_t *)uthash_malloc(sizeof(rtp_frame_t));
    if (frame) {
        frame->seq = seq;
        frame->packet = uthash_malloc(bytes);
        frame->resend_count = RTP_FRAME_RESEND_COUNT;
        frame->bytes = bytes;
        frame->timeout_count = RTP_FRAME_TIMEOUT_COUNT - 1;
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

int rtp_frame_list_insert(rtp_frame_t **rtp_frame_list, rtp_frame_t *frame) {
    int ret = -1;
    rtp_frame_t *s;

    if (frame) {
        int seq = frame->seq;

        HASH_FIND_INT(*rtp_frame_list, &seq, s);  /* seq already in the hash? */
        if (s == NULL) {
            s = frame;
            HASH_ADD_INT(*rtp_frame_list, seq, s);  /* seq is the key field */
            ret = 0;
        }
    }
    return ret;
}

void rtp_frame_list_pop(rtp_frame_t **rtp_frame_list, rtp_frame_t *frame) {
    if (frame) {
        HASH_DEL(*rtp_frame_list, frame);  /* frame: pointer to delete */
    }
}

rtp_frame_t *rtp_frame_list_find_by_seq(rtp_frame_t **rtp_frame_list, int seq) {
    rtp_frame_t *frame;

    HASH_FIND_INT(*rtp_frame_list, &seq, frame);  /* frame: output pointer */
    return frame;
}

void rtp_frame_list_delete(rtp_frame_t **rtp_frame_list, rtp_frame_t *frame) {
    if (frame) {
        HASH_DEL(*rtp_frame_list, frame);  /* frame: pointer to delete */
        rtp_frame_free(frame);
    }
}

void rtp_frame_list_delete_all(rtp_frame_t **rtp_frame_list) {
    rtp_frame_t *frame;
    rtp_frame_t *tmp;

    HASH_ITER(hh, *rtp_frame_list, frame, tmp) {
        rtp_frame_list_delete(rtp_frame_list, frame);  /* delete it (users advances to next) */
    }
}

void rtp_frame_list_reset(rtp_frame_t **rtp_frame_list) {
    rtp_frame_list_delete_all(rtp_frame_list);
}

int rtp_frame_list_delete_by_seq(rtp_frame_t **rtp_frame_list, int seq) {
    int ret = -1;
    rtp_frame_t *frame;

    frame = rtp_frame_list_find_by_seq(rtp_frame_list, seq);
    if (frame) {
        rtp_frame_list_delete(rtp_frame_list, frame);
        ret = 0;
    }
    return ret;
}

int rtp_frame_list_count(rtp_frame_t **rtp_frame_list) {
    return HASH_COUNT(*rtp_frame_list);
}

void rtp_frame_list_sort_by_bytes(rtp_frame_t **rtp_frame_list) {
    HASH_SORT(*rtp_frame_list, by_bytes);
}

void rtp_frame_list_sort_by_seq(rtp_frame_t **rtp_frame_list) {
    HASH_SORT(*rtp_frame_list, by_seq);
}

static void rtp_frame_print(rtp_frame_t *frame) {
    if (frame) {
        JLOG_INFO("----------------------------");
        JLOG_INFO_DUMP_HEX(frame->packet, frame->bytes, "seq %d: %d Bytes", frame->seq, frame->bytes);
    }
}

void rtp_frame_list_print_by_seq(rtp_frame_t **rtp_frame_list, int seq) {
    rtp_frame_t *frame;
    frame = rtp_frame_list_find_by_seq(rtp_frame_list, seq);
    if (frame) {
        rtp_frame_print(frame);
    }
}

void rtp_frame_list_print_all(rtp_frame_t **rtp_frame_list) {
    rtp_frame_t *frame;
    
    JLOG_INFO("rtp frame counts[%d]", rtp_frame_list_count(rtp_frame_list));
    for (frame = *rtp_frame_list; frame != NULL; frame = (rtp_frame_t *)(frame->hh.next)) {
        rtp_frame_print(frame);
    }
}

#include <aos/cli.h>


int test_rtpframe(int argc, char **argv) {
    static rtp_frame_t *test_frame_list = NULL;
    static int id = 1;
    rtp_frame_t *s;
    int temp;
    if (argc < 2) {
        printf("%s 1 frame size - add frame size\n", argv[0]);
        printf("%s 2 id frame size - add or rename frame by id\n", argv[0]);
        printf("%s 3 id - find frame\n", argv[0]);
        printf("%s 4 id - delete frame\n", argv[0]);
        printf("%s 5 - delete all frame\n", argv[0]);
        printf("%s 6 - sort items by bytes\n", argv[0]);
        printf("%s 7 - sort items by id\n", argv[0]);
        printf("%s 8 - print frame\n", argv[0]);
        printf("%s 9 - count frame\n", argv[0]);
    } else {
        switch (atoi(argv[1])) {
            case 1:
                s = rtp_frame_malloc(id++, argv[2], atoi(argv[3]));
                rtp_frame_list_insert(&test_frame_list, s);
                break;
            case 2:
                s = rtp_frame_malloc(atoi(argv[2]), argv[3], atoi(argv[4]));
                rtp_frame_list_insert(&test_frame_list, s);
                break;
            case 3:
                s = rtp_frame_list_find_by_seq(&test_frame_list, atoi(argv[2]));
                printf("packet: %s\n", s ? s->packet : "unknown");
                break;
            case 4:
                s = rtp_frame_list_find_by_seq(&test_frame_list, atoi(argv[2]));
                if (s) {
                    rtp_frame_list_delete(&test_frame_list, s);
                } else {
                    printf("id unknown\n");
                }
                break;
            case 5:
                rtp_frame_list_delete_all(&test_frame_list);
                break;
            case 6:
                rtp_frame_list_sort_by_bytes(&test_frame_list);
                break;
            case 7:
                rtp_frame_list_sort_by_seq(&test_frame_list);
                break;
            case 8:
                rtp_frame_list_print_all(&test_frame_list);
                break;
            case 9:
                temp = rtp_frame_list_count(&test_frame_list);
                printf("there are %d frame\n", temp);
                break;
        }
    }
    return 0;
}

ALIOS_CLI_CMD_REGISTER(test_rtpframe, test_rtpframe, test_rtpframe);